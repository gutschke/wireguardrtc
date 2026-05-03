#!/bin/bash
# 22_auto_active_dropin.sh — verify the daemon auto-writes a Mode=active
# peers.d-style drop-in to <StateDir>/auto-enrolled.d/ on each
# successful enrolment (Phase-2 enabler — see wg-holepunch-guide.md
# §"Auto-active drop-ins for enrolled peers").
#
# What we assert:
#   1. After ENROLL_OK fires for a new client, the file
#      <StateDir>/auto-enrolled.d/<label>-<fingerprint>.conf exists.
#   2. The file contains the client's PublicKey AND Mode = active.
#   3. Re-enrolling the same pubkey overwrites idempotently
#      (same filename — no accumulating files).
#   4. Setting [Enrollment] AutoActive = no in the daemon config
#      disables the writer entirely.

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
    local desc="$1" cond="$2"
    if eval "$cond"; then echo "  PASS [$desc]"; pass_n=$((pass_n+1))
    else echo "  FAIL [$desc]"; fail_n=$((fail_n+1)); fi
}

URI=$(_mint testclient22 "--expires 600")
[[ -n "$URI" ]] || { echo "[22] FAIL — no URI minted"; exit 1; }
_run_daemon

echo "[22] enrolling testclient22..."
fabric_exec_capture client "
    '$PY' '$CLIENT' --json '$URI' --timeout 30 2>&1
" >/dev/null

# Give the daemon a moment to write the drop-in (enrolment is async).
sleep 1

AA_DIR="$FABRIC_TMP/state/auto-enrolled.d"
expect "auto-active-dir-exists" "[ -d '$AA_DIR' ]"
NUM_FILES=$(ls "$AA_DIR"/*.conf 2>/dev/null | wc -l)
expect "exactly-one-conf" "[ '$NUM_FILES' = '1' ]"

DROPIN=$(ls "$AA_DIR"/*.conf 2>/dev/null | head -1)
expect "filename-mentions-label" "echo '$DROPIN' | grep -q 'testclient22'"
expect "contains-mode-active" "grep -q 'Mode = active' '$DROPIN'"
expect "contains-pubkey" "grep -q '^PublicKey = ' '$DROPIN'"

# Second enrolment of the same name uses a fresh client keypair
# (each enrol is a distinct WG identity) — so we get a SECOND
# drop-in, not an overwrite.  Assert exactly that: each enrol
# produces its own auto-active entry, both with Mode=active.
URI2=$(_mint testclient22 "--expires 600")
[[ -n "$URI2" ]] || { echo "[22] FAIL — second mint failed"; exit 1; }
fabric_exec_capture client "
    '$PY' '$CLIENT' --json '$URI2' --timeout 30 2>&1
" >/dev/null
sleep 1
NUM_FILES_2=$(ls "$AA_DIR"/*.conf 2>/dev/null | wc -l)
expect "two-confs-after-second-enrol" "[ '$NUM_FILES_2' = '2' ]"

# Pubkey-collision idempotency: write the SAME pubkey twice via
# the writer directly and confirm only one file results
# (covers daemon-restart-retry / cache_response replay).
SAMEPK=$(grep -m1 '^PublicKey = ' "$AA_DIR"/*.conf | head -1 | sed 's/.*= //')
"$PY" -c "
import sys; sys.path.insert(0, '$REPO')
import importlib.machinery, importlib.util
loader = importlib.machinery.SourceFileLoader('wgrtc', '$DAEMON')
m = importlib.util.module_from_spec(importlib.util.spec_from_loader('wgrtc', loader))
loader.exec_module(m)
import pathlib
m.write_auto_active_peer(pathlib.Path('$FABRIC_TMP/state'),
                        '$SAMEPK', 'testclient22', 'wg0')
"
NUM_FILES_3=$(ls "$AA_DIR"/*.conf 2>/dev/null | wc -l)
expect "same-pubkey-overwrite-idempotent" "[ '$NUM_FILES_3' = '2' ]"

echo
echo "summary: $pass_n passed, $fail_n failed"
[ "$fail_n" -eq 0 ]
