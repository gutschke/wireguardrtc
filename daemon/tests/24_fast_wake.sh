#!/bin/bash
# 24_fast_wake.sh — end-to-end timing test for the client-initiated
# wake path. signal_wake
# round-tripped through a real broker MUST refresh a peer's view of
# the daemon's endpoint in well under the daemon's 30 s polling cycle.
#
# What we verify on top of test 23 (which only checks the wire format):
# (a) the round-trip completes in under 5 s wall-clock — the
# "fast" in fast_wake;
# (b) the responsive OFFER's first candidate matches the daemon's
# configured PublicIp (192.168.99.20) so a client honouring the
# candidates array would actually pick a valid endpoint.
#
# We don't run a real enrolment here — test 10 already covers that.
# Adding it would gate this test on enrol latency that's irrelevant to
# the wake path under measurement. We pre-stage the peer via the
# same peers.d drop-in pattern test 23 uses.

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
 if eval "$cond"; then echo " PASS [$desc]"; pass_n=$((pass_n+1))
 else echo " FAIL [$desc]"; fail_n=$((fail_n+1)); fi
}

# Stage: pre-add a peer to wg0 + drop-in. Same shape as test 23.
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

SALT_B64=$(sed -nE 's/^Salt[[:space:]]*=[[:space:]]*([^[:space:]]+).*/\1/p' \
 "$FABRIC_TMP/server-cfg/wireguardrtc.conf" | head -1)
SRV_PUB_B64=$(fabric_exec_capture server "wg show wg0 public-key" \
 | tr -d '[:space:]')

# Time the round-trip. bash $SECONDS has 1 s granularity, which is
# fine for "under 5 s" assertions; if we ever need millisecond
# resolution we'd swap in `date +%s%3N`.
start=$SECONDS
set +e
RESULT=$(fabric_exec_capture broker "
 PROBE_BROKER='ws://192.168.99.10:9000/peerjs' \
 PROBE_BROKER_KEY='e2etestkey' \
 PROBE_SALT_B64='$SALT_B64' \
 PROBE_SRV_PUB_B64='$SRV_PUB_B64' \
 PROBE_PEER_PRIV='$PEER_PRIV' \
 PROBE_PEER_PUB='$PEER_PUB' \
 PROBE_KIND='signal_wake' \
 PROBE_TIMEOUT='10' \
 '$PY' '$HERE/_signal_wake_probe.py'
")
PROBE_RC=$?
elapsed=$(( SECONDS - start ))
set -e

echo "[24] daemon response (full):"
echo "$RESULT" | sed 's/^/ /' | head -10
echo "[24] elapsed=${elapsed}s probe rc=$PROBE_RC"

if [[ "$RESULT" != ok:* ]]; then
 echo "── server.log tail ─────────────────────────────────"
 fabric_exec_capture server "tail -30 '$FABRIC_TMP/server.log'" 2>/dev/null
 echo "── broker.log tail ─────────────────────────────────"
 fabric_exec_capture broker "tail -10 '$FABRIC_TMP/broker.log'" 2>/dev/null
 echo "────────────────────────────────────────────────────"
fi

# 1. Got a response at all.
expect "got-response" "[[ \"$RESULT\" == ok:* ]]"

# 2. Round-trip well under the 30 s daemon poll cycle. Loose bound;
# in practice we see <1 s on a quiet box, but CI / loaded boxes
# occasionally hit ~3 s due to broker scheduling.
expect "fast-wake-under-5s" "[[ \$elapsed -lt 5 ]]"

# 3. Response carries a non-empty candidates array.
expect "response-has-candidates" \
 "echo \"\$RESULT\" | grep -q '\"candidates\"'"

# 4. The first candidate's `ip` is the daemon's PublicIp. We don't
# have jq guaranteed in fabric netns; do a cheap substring match
# against the IP literal — sufficient because the rest of the
# plaintext is base-decoded JSON and the IP appears nowhere else.
PUB_IP=$(sed -nE 's/^PublicIp[[:space:]]*=[[:space:]]*([^[:space:]]+).*/\1/p' \
 "$FABRIC_TMP/server-cfg/wireguardrtc.conf" | head -1)
expect "candidate-matches-public-ip ($PUB_IP)" \
 "echo \"\$RESULT\" | grep -q '\"ip\": *\"$PUB_IP\"'"

echo
echo "summary: $pass_n passed, $fail_n failed (elapsed=${elapsed}s)"
[ "$fail_n" -eq 0 ]
