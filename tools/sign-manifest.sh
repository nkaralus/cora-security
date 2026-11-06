#!/usr/bin/env bash
# Sign blocklists/MANIFEST.json. Run ONLY on the offline signing machine (Dimgeon), never in CI.
#
#   tools/sign-manifest.sh            # checks, signs, commits blocklists/MANIFEST.json.minisig (you push)
#
# Refuses to sign unless:
#   * HEAD is exactly origin/main and the tree is clean (you sign what nodes will fetch)
#   * every committed list REBUILDS byte-for-byte from submissions/accepted/ with tools/cora_compile.py
#     (a bot commit that was tampered with cannot get your signature)
#   * every list hashes to its manifest entry
# The trusted comment is the exact form cora-sentinel requires:
#   cora-manifest repo:<repo> file:MANIFEST.json timestamp:<unix>
# Key: $CORA_MINISIGN_KEY (default ~/.minisign/cora-security.key). Public key: keys/cora-security.pub
set -euo pipefail

repo="nkaralus/cora-security"
key="${CORA_MINISIGN_KEY:-$HOME/.minisign/cora-security.key}"
cd "$(git rev-parse --show-toplevel)"
command -v minisign >/dev/null || { echo "minisign not installed (apt install minisign)" >&2; exit 1; }
[ -f "$key" ] || { echo "secret key not found: $key" >&2; exit 1; }
[ -f keys/cora-security.pub ] || { echo "keys/cora-security.pub missing: commit the public key first" >&2; exit 1; }

git fetch -q origin
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || { echo "HEAD is not origin/main: git pull --ff-only first" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "working tree is not clean" >&2; exit 1; }

python3 tools/cora_compile.py compile >/dev/null
if ! git diff --quiet -- blocklists; then
  echo "REFUSING TO SIGN: the committed lists do not rebuild from submissions/accepted/" >&2
  git --no-pager diff --stat -- blocklists >&2
  git checkout -q -- blocklists
  exit 1
fi

python3 - <<'PY'
import hashlib, json, pathlib, sys
m = json.loads(pathlib.Path("blocklists/MANIFEST.json").read_text())
for name, meta in sorted(m["lists"].items()):
    h = hashlib.sha256(pathlib.Path("blocklists", name).read_bytes()).hexdigest()
    if h != meta["sha256"]:
        sys.exit(f"REFUSING TO SIGN: {name} does not match its manifest hash")
    print(f"  {name:<28} {meta['entries']:>6} entries  {h[:12]}")
print(f"  from {m['accepted_reports']} accepted report(s), generated_from {m['generated_from']}")
PY

ts="$(date -u +%s)"
minisign -S -s "$key" -m blocklists/MANIFEST.json -x blocklists/MANIFEST.json.minisig \
  -t "cora-manifest repo:$repo file:MANIFEST.json timestamp:$ts"
minisign -V -q -p keys/cora-security.pub -m blocklists/MANIFEST.json -x blocklists/MANIFEST.json.minisig

git add blocklists/MANIFEST.json.minisig
git commit -q -m "blocklists: sign manifest (timestamp $ts)"
echo "signed and committed at timestamp $ts. Review with 'git show --stat', then: git push"
