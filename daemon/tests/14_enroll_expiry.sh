#!/bin/bash
# 14_enroll_expiry.sh — expired tokens are silently ignored (no leak of
# token existence to the requester).  The client observes a timeout, not
# an authenticated error.

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

# Mint with the minimum allowed expiry (60s).  Then forcibly mark it
# expired by editing the state file.  This avoids a 60s sleep in the test.
URI=$(_mint testclient "--expires 60")
[[ -n "$URI" ]] || { echo "[14] FAIL — no URI minted"; exit 1; }

fabric_exec_capture server "
    $PY -c '
import json, time, sys
p = \"$FABRIC_TMP/state/pending-tokens.json\"
with open(p) as f: data = json.load(f)
for t in data[\"tokens\"]:
    t[\"expires_at\"] = int(time.time()) - 60   # already expired
with open(p, \"w\") as f: json.dump(data, f, indent=2)
print(\"forcibly expired all pending tokens\")
'" >/dev/null

_run_daemon

echo "[14] enrolling against expired token (expecting timeout)..."
RESULT=$(fabric_exec_capture client "
    '$PY' '$CLIENT' --json '$URI' --timeout 10 2>&1
" || true)
echo "[14] client output:"; echo "$RESULT" | sed 's/^/    /' | head -10

KIND=$(echo "$RESULT" | $PY -c "import json,sys; print(json.load(sys.stdin)['kind'])" 2>/dev/null || echo "parse-fail")

if [[ "$KIND" == "timeout" ]]; then
    echo "[14] PASS — expired token silently ignored, client saw timeout"
    exit 0
fi
echo "[14] FAIL — expected kind=timeout, got kind=$KIND"
echo "─── server.log ───"; fabric_exec_capture server "tail -30 '$FABRIC_TMP/server.log'"
exit 1
