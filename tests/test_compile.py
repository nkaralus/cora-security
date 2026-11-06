"""Hermetic tests for tools/cora_compile.py. No network; uses the repo's committed schema."""
import copy
import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("cora_compile", REPO / "tools" / "cora_compile.py")
cc = importlib.util.module_from_spec(spec)
sys.modules["cora_compile"] = cc
spec.loader.exec_module(cc)

NEVER = "140.82.112.0/20 ; github\n8.8.8.0/24\ngithub.com\npypi.org\n"


@pytest.fixture
def root(tmp_path):
    (tmp_path / "schema").mkdir()
    shutil.copy(REPO / "schema" / "violation.schema.json", tmp_path / "schema")
    (tmp_path / "policy").mkdir()
    (tmp_path / "policy" / "never-block.txt").write_text(NEVER)
    (tmp_path / "submissions" / "accepted").mkdir(parents=True)
    return tmp_path


def make(kind="tracker_domain", entry="doubleclick.net", rid="0" * 32, **over):
    r = json.loads((REPO / "examples" / "violation.example.json").read_text())
    r["report_id"] = rid
    r["violation"]["type"] = kind
    r["violation"]["entry"] = entry
    r["violation"]["proto"] = "tcp"
    r["violation"]["via"] = "syn_tap"
    r["violation"]["destination"]["ip"] = "45.33.32.10"
    for path, val in over.items():
        node = r
        *parts, last = path.split("__")
        for p in parts:
            node = node[p]
        node[last] = val
    return r


def run(report, root):
    return cc.check_text(json.dumps(report), root)


def rid(n):
    return f"{n:032x}"


# ---------------------------------------------------------------- happy paths

def test_example_report_validates_against_committed_schema(root):
    report = json.loads((REPO / "examples" / "violation.example.json").read_text())
    cc.stage_validate(report, cc.load_schema(root))


def test_tracker_accepted(root):
    res = run(make(), root)
    assert res["ok"] and res["value"] == "doubleclick.net"
    assert res["list"] == "community-trackers.txt"


def test_subnet_accepted_and_normalized(root):
    res = run(make("rogue_subnet", "45.33.32.7/24"), root)
    assert res["ok"] and res["value"] == "45.33.32.0/24"


@pytest.mark.parametrize("entry", ["||ads.tracker.io^", "0.0.0.0 ads.tracker.io", "*.ads.tracker.io", "ADS.Tracker.IO."])
def test_domain_formats_normalize(root, entry):
    assert run(make(entry=entry), root)["value"] == "ads.tracker.io"


def test_fenced_issue_body(root):
    body = "Report from my node\n\n```json\n" + json.dumps(make()) + "\n```\nthanks"
    assert cc.check_text(body, root)["ok"]


# ---------------------------------------------------------------- parse + validate

def test_two_code_blocks_rejected(root):
    block = "```json\n" + json.dumps(make()) + "\n```"
    assert cc.check_text(block + "\n" + block, root)["stage"] == "parse"


def test_not_json_rejected(root):
    assert cc.check_text("hello", root)["stage"] == "parse"


def test_missing_required_field(root):
    r = make()
    del r["task_ref"]
    assert run(r, root)["stage"] == "validate"


def test_extra_field_rejected(root):
    r = make()
    r["hostname"] = "nick-desktop"
    assert run(r, root)["stage"] == "validate"


def test_bad_enum_rejected(root):
    assert run(make(violation__via="tcpdump"), root)["stage"] == "validate"


def test_allow_verdict_rejected(root):
    assert run(make(response__verdict="ALLOW"), root)["stage"] == "validate"


# ---------------------------------------------------------------- scrub

@pytest.mark.parametrize("over", [
    {"process": "/home/nick/bin/agent"},
    {"process": "agent@nick-laptop.lan"},
    {"process": "10.0.0.4"},
    {"response__policy": "nick@example.com"},
    {"response__policy": "aa:bb:cc:dd:ee:ff"},
    {"violation__list": "C:\\lists\\mine"},
    {"violation__list": "printer.local"},
])
def test_identifiers_scrubbed(root, over):
    assert run(make(**over), root)["stage"] == "scrub"


def test_bare_process_name_allowed(root):
    assert run(make(process="firefox-bin"), root)["ok"]


# ---------------------------------------------------------------- route

@pytest.mark.parametrize("entry", [
    "10.0.3.0/24", "192.168.1.0/24", "172.16.5.0/24", "100.64.1.0/24", "127.0.0.1",
    "169.254.0.0/16", "224.0.0.0/24", "198.51.100.0/24", "240.0.0.0/24",
    "fd00:1::/48", "fe80::/64", "2001:db8::/48", "::1",
])
def test_unroutable_rejected(root, entry):
    assert run(make("rogue_subnet", entry), root)["stage"] == "route"


@pytest.mark.parametrize("entry", ["45.0.0.0/8", "2a00::/16"])
def test_too_broad_rejected(root, entry):
    assert run(make("rogue_subnet", entry), root)["stage"] == "route"


def test_never_block_cidr_overlap(root):
    res = run(make("rogue_subnet", "140.82.114.0/24"), root)
    assert res["stage"] == "route" and "never-block" in res["reason"]


@pytest.mark.parametrize("entry", ["github.com", "api.github.com", "pypi.org"])
def test_never_block_domain(root, entry):
    assert run(make(entry=entry), root)["stage"] == "route"


def test_never_block_parent_domain(root, tmp_path):
    (root / "policy" / "never-block.txt").write_text("raw.githubusercontent.com\n")
    assert run(make(entry="githubusercontent.com"), root)["stage"] == "route"


@pytest.mark.parametrize("entry", ["printer.local", "nas.home.arpa", "localhost", "intranet", "x.internal"])
def test_local_domains_rejected(root, entry):
    assert run(make(entry=entry), root)["stage"] in {"route", "scrub"}


def test_leaked_private_destination(root):
    assert run(make(violation__destination__ip="192.168.1.20"), root)["stage"] == "route"


def test_ip_with_nonpublic_class_rejected(root):
    r = make(violation__destination__ip_class="private")
    assert run(r, root)["stage"] == "route"


def test_null_destination_ok(root):
    assert run(make(violation__destination__ip=None), root)["ok"]


def test_never_block_missing_fails_closed(root):
    (root / "policy" / "never-block.txt").unlink()
    with pytest.raises(SystemExit):
        run(make(), root)


# ---------------------------------------------------------------- accept / compile

def accept(root, report, *extra):
    p = root / "body.json"
    p.write_text(json.dumps(report))
    return cc.main(["--root", str(root), "accept", "--file", str(p), *extra])


def test_accept_then_duplicate(root):
    assert accept(root, make()) == 0
    assert accept(root, make()) == 1


def test_expect_sha_mismatch_refused(root):
    assert accept(root, make(), "--expect-sha", "f" * 64) == 1
    body = json.dumps(make())
    assert accept(root, make(), "--expect-sha", cc.body_sha256(body)) == 0


def test_compile_collapses_dedupes_and_is_deterministic(root):
    reports = [
        make("rogue_subnet", "45.33.32.0/25", rid(1)),
        make("rogue_subnet", "45.33.32.128/25", rid(2)),
        make("rogue_subnet", "45.33.32.0/25", rid(3)),
        make(entry="tracker.io", rid=rid(4)),
        make(entry="ads.tracker.io", rid=rid(5)),
        make(entry="other-ads.net", rid=rid(6)),
    ]
    for r in reports:
        assert accept(root, r) == 0
    assert cc.main(["--root", str(root), "compile"]) == 0

    bl = root / "blocklists"
    subnets = [l for l in (bl / "community-subnets.txt").read_text().splitlines() if not l.startswith("#")]
    trackers = [l for l in (bl / "community-trackers.txt").read_text().splitlines() if not l.startswith("#")]
    assert subnets == ["45.33.32.0/24"]
    assert trackers == ["other-ads.net", "tracker.io"]

    manifest = json.loads((bl / "MANIFEST.json").read_text())
    import hashlib
    for name, meta in manifest["lists"].items():
        assert meta["sha256"] == hashlib.sha256((bl / name).read_bytes()).hexdigest()
    assert manifest["lists"]["community-subnets.txt"]["sources"]["45.33.32.0/24"] == [rid(1), rid(2), rid(3)]
    assert manifest["lists"]["community-trackers.txt"]["sources"]["tracker.io"] == [rid(4), rid(5)]

    before = {p.name: p.read_bytes() for p in bl.iterdir()}
    cc.main(["--root", str(root), "compile"])
    assert before == {p.name: p.read_bytes() for p in bl.iterdir()}


def test_compile_drops_report_newly_on_never_block(root):
    assert accept(root, make(entry="cdn-shared.net", rid=rid(9))) == 0
    with open(root / "policy" / "never-block.txt", "a") as f:
        f.write("cdn-shared.net\n")
    cc.main(["--root", str(root), "compile"])
    text = (root / "blocklists" / "community-trackers.txt").read_text()
    assert "cdn-shared.net" not in text


def test_compile_drops_renamed_file(root):
    assert accept(root, make(rid=rid(7))) == 0
    src = root / "submissions" / "accepted" / f"{rid(7)}.json"
    src.rename(src.with_name(f"{rid(8)}.json"))
    accepted, dropped = cc.load_accepted(root)
    assert not accepted and dropped
