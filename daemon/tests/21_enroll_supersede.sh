#!/bin/bash
# 21_enroll_supersede.sh — same-name re-mint invalidates the previous
# unexpired token, prints a supersede warning, and removes the broker
# permit (if present).  See project_duplicate_label_policy memo.
#
# Workflow:
#   1. Mint token1 for "alice" — verify no supersede warning, URI emitted.
#   2. Mint token2 for "alice" — verify supersede warning on stderr, URI
#      emitted.
#   3. Start the daemon.
#   4. Run reference enroll_client with token1 — expect timeout (the
#      daemon silently ignores unknown / removed tokens, per the existing
#      anti-oracle stance — see test 14_enroll_expiry).
#   5. Run reference enroll_client with token2 — expect ENROLL_OK.

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

pass_n=0; fail_n=0
expect() {
    local desc="$1"; shift
    local cond="$1"; shift
    if eval "$cond"; then
        echo "  PASS [$desc]"; pass_n=$((pass_n+1))
    else
        echo "  FAIL [$desc]"; fail_n=$((fail_n+1))
        for line in "$@"; do echo "         $line"; done
    fi
}

# Run the daemon CLI directly so we can keep stderr separate from stdout
# (the _mint helper merges them).  Returns: stdout in $out, stderr in $err.
_mint_split() {
    local name="$1"
    local extra="${2:-}"
    local merged
    # bash 4 process-substitution: capture stderr to a tmp, stdout to a var.
    local tmp_err; tmp_err="$(mktemp -p "$FABRIC_TMP")"
    out=$(fabric_exec_capture server "
        WIREGUARDRTC_LOCK_FILE='$FABRIC_TMP/server.lock' \
        '$PY' '$DAEMON' \
            --config '$FABRIC_TMP/server-cfg/wireguardrtc.conf' \
            --peers-dir '$FABRIC_TMP/server-cfg/peers.d' \
            --enroll-token $name $extra 2>'$tmp_err'
    ")
    err=$(cat "$tmp_err"); rm -f "$tmp_err"
}

echo "[21] minting token1 for alice..."
_mint_split alice "--expires 600"
URI1=$(echo "$out" | grep -o 'wgrtc-enroll://[^[:space:]]*' | head -1)
expect "first-mint-emits-uri" "[ -n \"\$URI1\" ]" \
       "stdout was: $out" "stderr was: $err"
expect "first-mint-no-supersede-warning" \
       "! echo \"\$err\" | grep -q 'replaced previous'" \
       "stderr was: $err"

echo "[21] minting token2 for alice (re-mint)..."
sleep 1   # so created_at differs between the two tokens
_mint_split alice "--expires 600"
URI2=$(echo "$out" | grep -o 'wgrtc-enroll://[^[:space:]]*' | head -1)
expect "second-mint-emits-uri" "[ -n \"\$URI2\" ]" \
       "stdout was: $out" "stderr was: $err"
expect "second-mint-uri-differs" "[ \"\$URI1\" != \"\$URI2\" ]"
expect "second-mint-supersede-warning" \
       "echo \"\$err\" | grep -q 'replaced previous unexpired token'" \
       "stderr was: $err"

# After supersede, pending-tokens.json must contain exactly one alice
# entry whose token matches URI2 (not URI1).
echo "[21] checking pending-tokens.json post-supersede..."
state_json=$(fabric_exec_capture server "cat '$FABRIC_TMP/state/pending-tokens.json'")
alice_count=$(echo "$state_json" | "$PY" -c '
import json, sys
d = json.load(sys.stdin)
print(sum(1 for t in d.get("tokens", []) if t.get("name_hint") == "alice"))
')
expect "exactly-one-alice-token" "[ \"\$alice_count\" = \"1\" ]" \
       "state was: $state_json"

# Now spin up the daemon and verify token1 is silently rejected (timeout
# from the client perspective, mirroring 14_enroll_expiry's contract).
_run_daemon

echo "[21] enrolling with superseded token1 (expect timeout)..."
RESULT1=$(fabric_exec_capture client "
    '$PY' '$CLIENT' --json '$URI1' --timeout 10 2>&1
" || true)
KIND1=$(echo "$RESULT1" | "$PY" -c "import json,sys; print(json.load(sys.stdin)['kind'])" 2>/dev/null || echo "parse-fail")
expect "token1-rejected-as-timeout" "[ \"\$KIND1\" = \"timeout\" ]" \
       "client output: $RESULT1"

echo "[21] enrolling with current token2 (expect ENROLL_OK)..."
RESULT2=$(fabric_exec_capture client "
    '$PY' '$CLIENT' --json '$URI2' --timeout 30 2>&1
")
KIND2=$(echo "$RESULT2" | "$PY" -c "import json,sys; print(json.load(sys.stdin)['kind'])" 2>/dev/null || echo "parse-fail")
expect "token2-accepted" "[ \"\$KIND2\" = \"enroll_ok\" ]" \
       "client output: $RESULT2"

echo
echo "summary: $pass_n passed, $fail_n failed"
[ "$fail_n" -eq 0 ]
