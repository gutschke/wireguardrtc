#!/bin/bash
# 15_enroll_provision_fail.sh — ProvisionScript exits non-zero.
# Server returns authenticated ENROLL_ERR(PROVISION_FAILED).  The token
# is consumed (because we already won the atomic claim before invoking
# the script); admin must mint a fresh one to retry.

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

# Tell the topology helper to use a deliberately failing provision script
# instead of the working one.
ENROLL_PROVISION_SCRIPT="$FABRIC_TMP/fail-provision.sh"
. "$HERE/_enroll_topology.sh"

cat > "$FABRIC_TMP/fail-provision.sh" <<'EOF'
#!/bin/bash
echo "simulated provisioning failure" >&2
exit 7
EOF
chmod +x "$FABRIC_TMP/fail-provision.sh"

URI=$(_mint testclient)
[[ -n "$URI" ]] || { echo "[15] FAIL — no URI minted"; exit 1; }
_run_daemon

echo "[15] verify fail-provision.sh exists and is executable..."
fabric_exec_capture server "ls -la '$FABRIC_TMP/fail-provision.sh' 2>&1"
echo "[15] verify config points at it..."
fabric_exec_capture server "grep ProvisionScript '$FABRIC_TMP/server-cfg/wireguardrtc.conf'"

echo "[15] enrolling against broken provision script..."
set +e
RESULT=$(fabric_exec_capture client "'$PY' '$CLIENT' --json '$URI' --timeout 30" 2>&1)
client_rc=$?
set -uo pipefail
echo "[15] client_rc=$client_rc"
echo "[15] client output:"; echo "$RESULT" | sed 's/^/    /' | head -12

KIND=$(echo "$RESULT" | $PY -c "import json,sys; print(json.load(sys.stdin)['kind'])")
CODE=$(echo "$RESULT" | $PY -c "import json,sys; print(json.load(sys.stdin)['plaintext'].get('code',''))")

if [[ "$KIND" == "enroll_err" && "$CODE" == "PROVISION_FAILED" ]]; then
    # Verify the token is consumed (single-use, can't be reused even on failure)
    used=$(fabric_exec_capture server "$PY -c \"
import json
with open('$FABRIC_TMP/state/pending-tokens.json') as f: d=json.load(f)
print('USED' if d['tokens'][0]['used'] else 'NOT-USED')
\"")
    if [[ "$used" == "USED" ]]; then
        echo "[15] PASS — got authenticated PROVISION_FAILED, token consumed"
        exit 0
    fi
    echo "[15] FAIL — got PROVISION_FAILED but token not consumed"
    exit 1
fi
echo "[15] FAIL — kind=$KIND code=$CODE (expected enroll_err / PROVISION_FAILED)"
echo "─── server.log ───"; fabric_exec_capture server "tail -30 '$FABRIC_TMP/server.log'"
exit 1
