#!/usr/bin/env python3
"""cora_compile: turn cora.security.violation/v1 reports into community blocklists.

Stages (a report must clear each in order):
  1. validate  - JSON Schema Draft 2020-12 against schema/violation.schema.json
  2. scrub     - reject anything that looks like a personal or local identifier
  3. route     - reject unroutable/special targets and anything overlapping policy/never-block.txt
  4. aggregate - dedupe, collapse CIDRs, prune subdomains already covered by a parent
  5. emit      - flat lists in blocklists/ + blocklists/MANIFEST.json (deterministic bytes)

Subcommands:
  check   --body-env VAR | --file PATH  [--json-out PATH]   exit 0 ok / 1 rejected
  accept  --body-env VAR | --file PATH  [--expect-sha HEX]  writes submissions/accepted/<id>.json
  compile                                                  rebuilds lists from every accepted file
  render-comment RESULT.json                               markdown for the issue comment

Pure data processing: nothing from a submission is ever executed or interpolated into a shell.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import jsonschema

SCHEMA_ID = "cora.security.violation/v1"
MANIFEST_SCHEMA = "cora.security.blocklist-manifest/v1"
MAX_PAYLOAD = 16 * 1024
BROADEST_V4 = 16  # community entries may not be broader than /16 (v4) or /32 (v6)
BROADEST_V6 = 32
OUTPUTS = {"rogue_subnet": "community-subnets.txt", "tracker_domain": "community-trackers.txt"}
DEFAULT_ROOT = Path(__file__).resolve().parent.parent

# Explicit special-purpose ranges. Checked by overlap in addition to ipaddress.is_global,
# so behaviour does not drift between Python patch releases.
SPECIAL_NETS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "100::/64", "2001::/23",
    "2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8",
)]

FENCE = re.compile(r"```(?:json)?[ \t]*\r?\n(.*?)\r?\n```", re.S)
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9._+:-]{1,64}$")
LIST_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
IPV4_LITERAL = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PII_PATTERNS = [
    ("email address", re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")),
    ("MAC address", re.compile(r"\b[0-9a-f]{2}([:-])(?:[0-9a-f]{2}\1){4}[0-9a-f]{2}\b", re.I)),
    ("home directory", re.compile(r"/(?:home|Users|root)/", re.I)),
    ("filesystem path", re.compile(r"(?:^|[\s\"'=])(?:~/|/[A-Za-z]|[A-Za-z]:\\)")),
    ("local hostname", re.compile(
        r"\blocalhost\b|\.(?:local|lan|home|internal|localdomain|corp)\b|\.home\.arpa\b", re.I)),
]
LOCAL_SUFFIXES = (".local", ".lan", ".home", ".internal", ".localdomain", ".corp",
                  ".home.arpa", ".localhost", ".test", ".example", ".invalid", ".onion")


class Rejected(Exception):
    def __init__(self, stage: str, reason: str):
        super().__init__(f"{stage}: {reason}")
        self.stage = stage
        self.reason = reason


@dataclass(frozen=True)
class Accepted:
    report_id: str
    kind: str     # rogue_subnet | tracker_domain
    value: str    # normalized CIDR or domain
    observed_hour: str
    report: dict


# ---------------------------------------------------------------- loading

def load_schema(root: Path) -> dict:
    schema = json.loads((root / "schema" / "violation.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    return schema


@dataclass
class NeverBlock:
    nets: list
    domains: set


def load_never_block(root: Path) -> NeverBlock:
    path = root / "policy" / "never-block.txt"
    if not path.is_file():
        raise SystemExit(f"fail-closed: {path} is missing, refusing to compile")
    nets, domains = [], set()
    for lineno, raw in enumerate(path.read_text().splitlines(), 1):
        line = re.split(r"[#;]", raw, maxsplit=1)[0].strip().lower()
        if not line:
            continue
        try:
            nets.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            if not _is_domain(line):
                raise SystemExit(f"{path}:{lineno}: not a CIDR, IP or domain: {raw!r}")
            domains.add(line)
    return NeverBlock(nets, domains)


def extract_report(text: str) -> dict:
    blocks = FENCE.findall(text or "")
    if len(blocks) > 1:
        raise Rejected("parse", "more than one code block; submit exactly one report per issue")
    raw = blocks[0] if blocks else (text or "").strip()
    if len(raw.encode()) > MAX_PAYLOAD:
        raise Rejected("parse", f"payload larger than {MAX_PAYLOAD} bytes")
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        raise Rejected("parse", f"not valid JSON ({e.msg}, line {e.lineno})")
    if not isinstance(obj, dict):
        raise Rejected("parse", "top level must be a JSON object")
    return obj


def body_sha256(text: str) -> str:
    return hashlib.sha256((text or "").encode()).hexdigest()


# ---------------------------------------------------------------- stage 1

def stage_validate(report: dict, schema: dict) -> None:
    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(report), key=lambda e: [str(p) for p in e.path])
    if errors:
        parts = [f"{'/'.join(map(str, e.path)) or '<root>'}: {e.message}" for e in errors[:5]]
        more = f" (+{len(errors) - 5} more)" if len(errors) > 5 else ""
        raise Rejected("validate", "; ".join(parts) + more)
    if report["response"]["verdict"] == "ALLOW":
        raise Rejected("validate", "verdict ALLOW means the node judged it benign; not a violation")


# ---------------------------------------------------------------- stage 2

def _strings(obj, path=""):
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _strings(v, f"{path}/{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _strings(v, f"{path}/{i}")


def stage_scrub(report: dict) -> None:
    for path, value in _strings(report):
        if path == "/violation/entry":
            continue  # shape-checked in the route stage; a domain there is the point
        for label, pattern in PII_PATTERNS:
            if pattern.search(value):
                raise Rejected("scrub", f"{path} contains what looks like a {label}")
    for field in ("process",):
        v = report.get(field)
        if v is not None and not SAFE_TOKEN.match(v):
            raise Rejected("scrub", f"/{field} must be a bare executable name")
    policy = report["response"].get("policy")
    if policy is not None and not SAFE_TOKEN.match(policy):
        raise Rejected("scrub", "/response/policy must be a bare policy identifier")
    if not LIST_NAME.match(report["violation"]["list"]):
        raise Rejected("scrub", "/violation/list must be a bare list name")
    for path, value in (("/process", report.get("process")),
                        ("/response/policy", policy),
                        ("/violation/list", report["violation"]["list"])):
        if value and IPV4_LITERAL.search(value):
            raise Rejected("scrub", f"{path} contains an IP address literal")


# ---------------------------------------------------------------- stage 3

def _is_domain(s: str) -> bool:
    if len(s) > 253 or "." not in s:
        return False
    labels = s.split(".")
    return all(LABEL.match(l) for l in labels) and re.fullmatch(r"[a-z]{2,63}|xn--[a-z0-9-]+", labels[-1]) is not None


def normalize_domain(entry: str) -> str:
    s = entry.strip().lower()
    hosts = re.fullmatch(r"(?:0\.0\.0\.0|127\.0\.0\.1|::1?|::)\s+(\S+)", s)
    if hosts:
        s = hosts.group(1)
    if s.startswith("||"):
        s = s[2:]
    s = s.rstrip("^").removeprefix("*.").rstrip(".")
    if not _is_domain(s):
        raise Rejected("route", f"tracker entry {entry!r} is not a valid registrable domain")
    if s.endswith(LOCAL_SUFFIXES) or s in {"localhost", "home.arpa"}:
        raise Rejected("route", f"tracker entry {entry!r} is a local/reserved name")
    return s


def _special(net) -> bool:
    if net.is_multicast or net.is_loopback or net.is_link_local or net.is_unspecified:
        return True
    if not net.is_global:
        return True
    return any(net.version == s.version and net.overlaps(s) for s in SPECIAL_NETS)


def normalize_subnet(entry: str):
    s = re.split(r"[;#]", entry, maxsplit=1)[0].strip()
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        raise Rejected("route", f"rogue_subnet entry {entry!r} is not a CIDR or IP")
    broadest = BROADEST_V4 if net.version == 4 else BROADEST_V6
    if net.prefixlen < broadest:
        raise Rejected("route", f"{net} is broader than /{broadest}; too wide for community intel")
    if _special(net):
        raise Rejected("route", f"{net} is unroutable or special-purpose; local intel stays local")
    return net


def _domain_conflict(domain: str, protected: set) -> str | None:
    for p in protected:
        if domain == p or domain.endswith("." + p) or p.endswith("." + domain):
            return p
    return None


def stage_route(report: dict, never: NeverBlock) -> tuple[str, str]:
    v = report["violation"]
    dest = v["destination"]
    if dest["ip"] is not None:
        try:
            ip = ipaddress.ip_address(dest["ip"])
        except ValueError:
            raise Rejected("route", "/violation/destination/ip is not an IP address")
        if dest["ip_class"] != "public" or _special(ipaddress.ip_network(ip)):
            raise Rejected("route", "destination ip must be null unless it is a globally routable public address")

    if v["type"] == "rogue_subnet":
        net = normalize_subnet(v["entry"])
        for p in never.nets:
            if p.version == net.version and p.overlaps(net):
                raise Rejected("route", f"{net} overlaps never-block {p}")
        return v["type"], str(net)

    domain = normalize_domain(v["entry"])
    hit = _domain_conflict(domain, never.domains)
    if hit:
        raise Rejected("route", f"{domain} conflicts with never-block {hit}")
    return v["type"], domain


# ---------------------------------------------------------------- pipeline

def process(report: dict, schema: dict, never: NeverBlock) -> Accepted:
    stage_validate(report, schema)
    stage_scrub(report)
    kind, value = stage_route(report, never)
    return Accepted(report["report_id"], kind, value, report["observed_hour"], report)


def check_text(text: str, root: Path) -> dict:
    result = {"ok": False, "body_sha256": body_sha256(text)}
    try:
        acc = process(extract_report(text), load_schema(root), load_never_block(root))
    except Rejected as r:
        result.update(stage=r.stage, reason=r.reason)
        return result
    if (root / "submissions" / "accepted" / f"{acc.report_id}.json").exists():
        result.update(stage="dedupe", reason=f"report_id {acc.report_id} was already accepted")
        return result
    result.update(ok=True, report_id=acc.report_id, kind=acc.kind, value=acc.value,
                  list=OUTPUTS[acc.kind])
    return result


# ---------------------------------------------------------------- stage 4

def load_accepted(root: Path) -> tuple[list[Accepted], list[str]]:
    schema, never = load_schema(root), load_never_block(root)
    accepted, dropped = [], []
    for path in sorted((root / "submissions" / "accepted").glob("*.json")):
        try:
            report = json.loads(path.read_text())
            acc = process(report, schema, never)
            if path.stem != acc.report_id:
                raise Rejected("dedupe", "file name does not match report_id")
            accepted.append(acc)
        except (Rejected, json.JSONDecodeError, KeyError) as e:
            dropped.append(f"{path.name}: {e}")  # e.g. never-block grew since acceptance
    return accepted, dropped


def aggregate(accepted: list[Accepted]) -> dict[str, dict[str, list[str]]]:
    """Return {output_file: {entry: [report_ids]}} with sorted, collapsed entries."""
    out: dict[str, dict[str, list[str]]] = {}

    nets = [(ipaddress.ip_network(a.value), a.report_id) for a in accepted if a.kind == "rogue_subnet"]
    collapsed = []
    for version in (4, 6):
        collapsed += list(ipaddress.collapse_addresses(n for n, _ in nets if n.version == version))
    out[OUTPUTS["rogue_subnet"]] = {
        str(c): sorted({rid for n, rid in nets if n.version == c.version and n.subnet_of(c)})
        for c in collapsed
    }

    doms = [(a.value, a.report_id) for a in accepted if a.kind == "tracker_domain"]
    names = {d for d, _ in doms}
    kept = sorted(d for d in names if not any(d.endswith("." + p) for p in names if p != d))
    out[OUTPUTS["tracker_domain"]] = {
        k: sorted({rid for d, rid in doms if d == k or d.endswith("." + k)}) for k in kept
    }
    return out


# ---------------------------------------------------------------- stage 5

def render_list(name: str, entries: list[str], n_reports: int, generated_from: str) -> str:
    stem = name.rsplit(".", 1)[0]
    head = [
        f"# {stem}: compiled by tools/cora_compile.py. DO NOT EDIT; regenerate instead.",
        f"# sources: {n_reports} accepted report(s) in submissions/accepted/",
        f"# generated-from: {generated_from}",
    ]
    return "\n".join(head + entries) + "\n"


def emit(root: Path, accepted: list[Accepted]) -> dict:
    agg = aggregate(accepted)
    generated_from = max((a.observed_hour for a in accepted), default="none")
    manifest = {"schema": MANIFEST_SCHEMA, "generated_from": generated_from,
                "accepted_reports": len(accepted), "lists": {}}
    bl = root / "blocklists"
    bl.mkdir(exist_ok=True)
    for name in sorted(agg):
        entries = list(agg[name])
        body = render_list(name, entries, len(accepted), generated_from)
        path = bl / name
        if not path.exists() or path.read_text() != body:
            path.write_text(body)
        manifest["lists"][name] = {
            "sha256": hashlib.sha256(body.encode()).hexdigest(),
            "entries": len(entries),
            "sources": agg[name],
        }
    (bl / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


# ---------------------------------------------------------------- CLI

def _read_input(args) -> str:
    if args.body_env:
        return os.environ.get(args.body_env, "")
    return Path(args.file).read_text()


def render_comment(result: dict) -> str:
    marker = f"<!-- cora-sha256:{result['body_sha256']} -->"
    if result["ok"]:
        return (f"{marker}\n**cora-ingest: validated** \u2705\n\n"
                f"Proposed `{result['value']}` \u2192 `blocklists/{result['list']}` "
                f"(report `{result['report_id']}`).\n\n"
                "A maintainer applying `accepted` will commit exactly this entry. "
                "Editing the issue re-runs validation and voids any earlier review.")
    return (f"{marker}\n**cora-ingest: rejected** \u274c at stage `{result['stage']}`\n\n"
            f"> {result['reason']}\n\nFix the report and edit this issue to re-run validation. "
            "Format: see `docs/violation-reports.md`.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="cora_compile")
    ap.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("check", "accept"):
        p = sub.add_parser(name)
        g = p.add_mutually_exclusive_group(required=True)
        g.add_argument("--body-env")
        g.add_argument("--file")
        if name == "check":
            p.add_argument("--json-out", type=Path)
        else:
            p.add_argument("--expect-sha", default=None,
                           help="refuse unless the body hashes to the last validated comment's marker")
    sub.add_parser("compile")
    rc = sub.add_parser("render-comment")
    rc.add_argument("result", type=Path)
    args = ap.parse_args(argv)
    root = args.root.resolve()

    if args.cmd == "render-comment":
        print(render_comment(json.loads(args.result.read_text())))
        return 0

    if args.cmd == "compile":
        accepted, dropped = load_accepted(root)
        manifest = emit(root, accepted)
        for d in dropped:
            print(f"dropped: {d}", file=sys.stderr)
        for name, meta in manifest["lists"].items():
            print(f"{name}: {meta['entries']} entries")
        return 0

    text = _read_input(args)
    result = check_text(text, root)

    if args.cmd == "check":
        if args.json_out:
            args.json_out.write_text(json.dumps(result, indent=2))
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 1

    # accept
    if args.expect_sha is not None and args.expect_sha != result["body_sha256"]:
        print("refused: issue body changed after the last validation; re-review it", file=sys.stderr)
        return 1
    if not result["ok"]:
        print(f"refused: {result['stage']}: {result['reason']}", file=sys.stderr)
        return 1
    report = extract_report(text)
    dest = root / "submissions" / "accepted" / f"{result['report_id']}.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(result["report_id"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
