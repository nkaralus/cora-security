#!/usr/bin/env bash
# Rotate the cora-security signing keys. Run on the signing machine with the STANDBY key's USB mounted.
#
#   tools/sign-rotation.sh --standby-key /media/usb/cora-security.standby.key \
#                          --new-standby-pub /media/usb/next.pub  [--compromised-after UNIX]
#
# What it writes (signed by the CURRENT standby key, the only key nodes accept for this):
#   keys/rotation-<n>.json        active := current standby, standby := --new-standby-pub, revokes the old active
#   keys/rotation-<n>.json.minisig
#   keys/cora-security.pub / keys/cora-security.standby.pub   updated to the NEW pair (for humans and the
#                                 signing scripts; nodes trust only their /etc genesis pins plus this signed chain)
#
# Planned rotation or a LOST active key: omit --compromised-after.
# Active key STOLEN: pass --compromised-after <the last manifest timestamp YOU signed>. Every node that applied a
# manifest signed later than that purges those lists at once and takes your next manifest over its delta caps.
# Every timestamp ever signed, newest first (compare against what you remember signing):
#   git log -p --format= -- blocklists/MANIFEST.json.minisig | grep '^+trusted comment'
#
# Before running: generate the next standby key ON THE USB, never on this machine's disk:
#   minisign -G -p /media/usb/next.pub -s /media/usb/next.key
# After: the old standby key becomes the ACTIVE key. Copy it to ~/.minisign/cora-security.key, re-sign the
# manifest with tools/sign-manifest.sh, then push both commits together.
set -euo pipefail

repo="nkaralus/cora-security"
standby_key="" new_standby_pub="" compromised_after="null"
while [ $# -gt 0 ]; do
  case "$1" in
    --standby-key) standby_key="${2:?}"; shift 2 ;;
    --new-standby-pub) new_standby_pub="${2:?}"; shift 2 ;;
    --compromised-after) compromised_after="${2:?}"; shift 2 ;;
    -h|--help) sed -n '2,22p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
[ -n "$standby_key" ] && [ -n "$new_standby_pub" ] || { echo "need --standby-key and --new-standby-pub (see --help)" >&2; exit 2; }
[[ "$compromised_after" = null || "$compromised_after" =~ ^[0-9]+$ ]] || { echo "--compromised-after must be a unix time" >&2; exit 2; }

cd "$(git rev-parse --show-toplevel)"
command -v minisign >/dev/null || { echo "minisign not installed" >&2; exit 1; }
for f in keys/cora-security.pub keys/cora-security.standby.pub "$standby_key" "$new_standby_pub"; do
  [ -f "$f" ] || { echo "missing: $f" >&2; exit 1; }
done
git fetch -q origin
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || { echo "HEAD is not origin/main: git pull --ff-only first" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "working tree is not clean" >&2; exit 1; }

n=1
while [ -e "keys/rotation-$n.json" ]; do n=$((n + 1)); done
ts="$(date -u +%s)"

python3 - "$n" "$compromised_after" "$new_standby_pub" <<'PY'
import base64, json, sys, pathlib
n, ca, new_pub = int(sys.argv[1]), sys.argv[2], sys.argv[3]
def key(path):
    line = [l for l in pathlib.Path(path).read_text().splitlines() if l.strip()][-1].strip()
    raw = base64.b64decode(line, validate=True)
    assert len(raw) == 42 and raw[:2] == b"Ed", f"{path}: not a minisign public key"
    return line, raw[2:10][::-1].hex().upper()
active, active_id = key("keys/cora-security.pub")
standby, standby_id = key("keys/cora-security.standby.pub")
new, new_id = key(new_pub)
if new_id in (active_id, standby_id):
    sys.exit("the new standby key must be a NEW key")
body = {"schema": "cora.security.key-rotation/v1", "epoch": n, "active": standby, "standby": new,
        "revokes": [active_id], "compromised_after": None if ca == "null" else int(ca)}
pathlib.Path(f"keys/rotation-{n}.json").write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
print(f"  epoch {n}: active {active_id} -> {standby_id}, new standby {new_id}, revokes {active_id}"
      + ("" if ca == "null" else f", COMPROMISED after {ca}"))
PY

minisign -S -s "$standby_key" -m "keys/rotation-$n.json" -x "keys/rotation-$n.json.minisig" \
  -t "cora-keyrotation repo:$repo epoch:$n timestamp:$ts"
minisign -V -q -p keys/cora-security.standby.pub -m "keys/rotation-$n.json" -x "keys/rotation-$n.json.minisig"

cp keys/cora-security.standby.pub keys/cora-security.pub
cp "$new_standby_pub" keys/cora-security.standby.pub
git add keys
git commit -q -m "keys: rotation epoch $n (timestamp $ts)"
cat <<MSG
rotation epoch $n committed (not pushed). Next:
  1. cp $standby_key ~/.minisign/cora-security.key        # the old standby is the ACTIVE key now
  2. tools/sign-manifest.sh                                # re-sign the manifest with it
  3. git push                                              # both commits together
  4. the new standby key stays on the USB; reprint the cold backup
MSG
