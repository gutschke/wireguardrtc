#!/bin/bash
# 12_enroll_replay.sh — retry safety: legitimate client retries with the
# same token + same keypair and gets the cached ENROLL_OK response (which
# only it can decrypt).  The token is single-use, so the server must
# remember its previous answer rather than reject the retry.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
DAEMON="${DAEMON:-$REPO/wireguardrtc}"
PY="${PY:-$REPO/venv/bin/python3}"
FABRIC_SH="$HERE/fabric.sh"
CLIENT="$HERE/enroll_client.py"

if [[ -z "${PEERJS:-}" ]]; then
    if command -v peerjs >/dev/null 2>&1; then PEERJS=$(command -v peerjs)
    elif [[ -x "$HERE/node_modules/.bin/peerjs" ]]; then PEERJS="$HERE/node_modules/.bin/peerjs"
    else echo "error: peerjs not found" >&2; exit 2; fi
fi
[[ -x "$PY" && -x "$DAEMON" && -x "$CLIENT" ]] || { echo "missing prereq" >&2; exit 2; }

if [[ -z "${WGRTC_FABRIC_INSIDE:-}" ]]; then
    export PEERJS DAEMON PY
    exec "$FABRIC_SH" "$0" "$@"
fi
source "$FABRIC_SH"

. "$HERE/_enroll_topology.sh"

URI=$(_mint testclient)
[[ -n "$URI" ]] || { echo "[12] FAIL — no URI minted"; exit 1; }
_run_daemon

# Run both enrolment attempts inside one Python process on `client` —
# this way we keep the keypair in memory across the two attempts.
RESULT=$(fabric_exec_capture client "
    '$PY' -c \"
import sys, json, asyncio
sys.path.insert(0, '$HERE')
from enroll_client import enroll, parse_enroll_uri
from nacl.bindings import crypto_box_keypair

uri = parse_enroll_uri('$URI')
pub, priv = crypto_box_keypair()

# Attempt 1 — should succeed.
r1 = asyncio.run(enroll(uri, hint='first', client_keypair=(pub, priv), timeout=30))

# Attempt 2 — same keypair, same token.  Server should serve cached response.
r2 = asyncio.run(enroll(uri, hint='retry', client_keypair=(pub, priv), timeout=30))

out = {
    'r1_kind':    r1['kind'],
    'r1_address': r1.get('plaintext', {}).get('address',''),
    'r2_kind':    r2['kind'],
    'r2_address': r2.get('plaintext', {}).get('address',''),
    'r2_code':    r2.get('plaintext', {}).get('code',''),
    'r2_note':    r2.get('plaintext', {}).get('note',''),
}
print(json.dumps(out))
\"")

echo "[12] result:"; echo "$RESULT" | sed 's/^/    /'

R1_KIND=$(echo "$RESULT" | $PY -c "import json,sys; print(json.load(sys.stdin)['r1_kind'])")
R1_ADDR=$(echo "$RESULT" | $PY -c "import json,sys; print(json.load(sys.stdin)['r1_address'])")
R2_KIND=$(echo "$RESULT" | $PY -c "import json,sys; print(json.load(sys.stdin)['r2_kind'])")
R2_ADDR=$(echo "$RESULT" | $PY -c "import json,sys; print(json.load(sys.stdin)['r2_address'])")

if [[ "$R1_KIND" == "enroll_ok" && "$R2_KIND" == "enroll_ok" \
      && "$R1_ADDR" == "$R2_ADDR" && -n "$R1_ADDR" ]]; then
    echo "[12] PASS — retry returned identical cached ENROLL_OK ($R2_ADDR)"
    exit 0
fi
echo "[12] FAIL — first=$R1_KIND ($R1_ADDR) retry=$R2_KIND ($R2_ADDR)"
echo "─── server.log ───"; fabric_exec_capture server "tail -30 '$FABRIC_TMP/server.log'"
exit 1
