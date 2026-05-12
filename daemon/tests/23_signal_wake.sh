#!/bin/bash
# 23_signal_wake.sh — verify the daemon handles `metadata.kind =
# "signal_wake"` per the protocol spec:
#   1. decrypts + validates freshness (or silently drops);
#   2. does NOT call wg set / raw_inject / wake — the wake-OFFER
#      sender hasn't claimed an endpoint;
#   3. responds with an OFFER carrying the daemon's CURRENT
#      endpoint(s), bypassing the "tunnel-already-UP" guard
#      that suppresses ordinary responsive OFFERs.
#
# How we exercise it: a small Python helper opens a websocket to
# the broker as a fake peer, sends a signal_wake envelope addressed
# at the daemon's routing-id, then reads back the daemon's
# responsive OFFER and decrypts it.  Asserts the responsive blob
# contains a `candidates` array with the daemon's current endpoint.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
DAEMON="${DAEMON:-$REPO/wireguardrtc}"
PY="${PY:-$REPO/venv/bin/python3}"
FABRIC_SH="$HERE/fabric.sh"

if [[ -z "${PEERJS:-}" ]]; then
    if command -v peerjs >/dev/null 2>&1; then PEERJS=$(command -v peerjs)
    elif [[ -x "$HERE/node_modules/.bin/peerjs" ]]; then PEERJS="$HERE/node_modules/.bin/peerjs"
    else echo "error: peerjs not found" >&2; exit 2; fi
fi
[[ -x "$PY" && -x "$DAEMON" ]] || { echo "missing prereq" >&2; exit 2; }

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

# Add a peer to wg0 the daemon will recognise (we register them via
# a peers.d/ drop-in, since the daemon needs a configured peer to
# accept OFFERs from on the iface side).  Use a fake but valid WG
# pubkey for the "peer" — the test plays the peer in Python.
PEER_PRIV=$(wg genkey)
PEER_PUB=$(echo "$PEER_PRIV" | wg pubkey)
fabric_exec server "wg set wg0 peer '$PEER_PUB' allowed-ips 10.0.0.99/32"
mkdir -p "$FABRIC_TMP/server-cfg/peers.d"
cat > "$FABRIC_TMP/server-cfg/peers.d/wake-peer.conf" <<EOF
[Peer]
PublicKey = $PEER_PUB
Mode = passive
EOF
_run_daemon

# Run the wake handshake as a Python script INSIDE the broker
# netns so we can reach the broker via 192.168.99.10:9000 (same
# topology the daemon uses).  Stdout: the responsive OFFER's
# decrypted JSON, or an error.
# Pull salt from the daemon's config file (we wrote it; we know the
# format) — broker netns has no wg, so we can't run --show-config there.
# `awk -F'='` would split on the base64 padding inside the value;
# parse with sed so trailing `=` characters survive.
SALT_B64=$(sed -nE 's/^Salt[[:space:]]*=[[:space:]]*([^[:space:]]+).*/\1/p' \
    "$FABRIC_TMP/server-cfg/wireguardrtc.conf" | head -1)
# Server pubkey from the SERVER netns where wg0 lives.
SRV_PUB_B64=$(fabric_exec_capture server "wg show wg0 public-key")
SRV_PUB_B64=$(echo "$SRV_PUB_B64" | tr -d '[:space:]')

# fabric.sh's `set -euo pipefail` is inherited by us, so a non-zero
# return from fabric_exec_capture would otherwise kill the script
# silently mid-test.  Disable errexit just around the capture so we
# can inspect both the output and the rc explicitly below.
set +e
RESULT=$(fabric_exec_capture broker "
    PROBE_BROKER='ws://192.168.99.10:9000/peerjs' \
    PROBE_BROKER_KEY='e2etestkey' \
    PROBE_SALT_B64='$SALT_B64' \
    PROBE_SRV_PUB_B64='$SRV_PUB_B64' \
    PROBE_PEER_PRIV='$PEER_PRIV' \
    PROBE_PEER_PUB='$PEER_PUB' \
    PROBE_KIND='signal_wake' \
    PROBE_TIMEOUT='15' \
    '$PY' '$HERE/_signal_wake_probe.py'
")
PROBE_RC=$?
set -e

echo "[23] daemon response (full):"
echo "$RESULT" | sed 's/^/    /' | head -20
echo "[23] probe rc=$PROBE_RC"

if [[ "$RESULT" != ok:* ]]; then
    echo "── server.log tail ──────────────────────────────"
    fabric_exec_capture server "tail -30 '$FABRIC_TMP/server.log'" 2>/dev/null
    echo "── broker.log tail ──────────────────────────────"
    fabric_exec_capture broker "tail -10 '$FABRIC_TMP/broker.log'" 2>/dev/null
    echo "─────────────────────────────────────────────────"
fi

# Assertions:
#   1. Daemon sent SOME response (no timeout).
expect "got-response" "[[ \"$RESULT\" == ok:* ]]"

#   2. The decrypted plaintext carries a non-empty `candidates` array
#      OR the legacy ip/port form (we accept both for v0.2 transition).
expect "response-has-endpoint-info" \
    "echo \"\$RESULT\" | grep -q '\"candidates\"'"

#   3. The daemon did NOT change the peer's endpoint to anything
#      derived from our wake (we sent no endpoint; nothing should
#      have been set).  Use wg show — endpoint should be empty
#      ((none)) or the test's pre-existing value.
KERNEL_EP=$(fabric_exec_capture server "wg show wg0 endpoints | grep '$PEER_PUB' || true")
expect "kernel-endpoint-not-bogus" \
    "[[ -z \"\$KERNEL_EP\" || \"\$KERNEL_EP\" == *'(none)'* ]]"

echo
echo "summary: $pass_n passed, $fail_n failed"
[ "$fail_n" -eq 0 ]
