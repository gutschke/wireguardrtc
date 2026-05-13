#!/bin/bash
# 30_fabric_cascade.sh — 3-daemon transit-routing cascade test.
#
# Topology (single L2, single wg interface per host, no NAT):
#
#       broker  ──┐
#                 │
#       A ───────┼───── B ───────┼───── C
#                 │              │
#                 └─ all on flat 192.168.99.0/24 ──
#
# WireGuard overlay:
#       A: wg0  10.0.0.1/24
#          [Peer B] AllowedIPs = 10.0.0.0/24      (everything in overlay via B)
#       B: wg0  10.0.0.2/24    (IP forwarding ON)
#          [Peer A] AllowedIPs = 10.0.0.1/32
#          [Peer C] AllowedIPs = 10.0.0.3/32
#       C: wg0  10.0.0.3/24
#          [Peer B] AllowedIPs = 10.0.0.0/24      (everything via B)
#
# wgrtc on every host manages a SINGLE WG interface — the daemon's known
# multi-interface limitation does not apply here.  The cascade is at the
# WG-overlay level: A and C never directly handshake; B is transit.
#
# Validates:
#   - wgrtc holds both A↔B and B↔C handshakes up simultaneously on B.
#   - 3-peer mesh signaling works (each host's selected iface routes-id
#     reaches the other two through PeerJS).
#   - C can reach 10.0.0.1 (A's wg-IP) via B as transit.
#
# Does NOT test:
#   - The daemon's multi-interface case (B running TWO wg interfaces, one
#     per "side" of the cascade).  See CLAUDE.md invariant 5 / daemon
#     source comment "Future versions should open one PeerJS connection
#     per interface."  Out of scope for D3.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
DAEMON="${DAEMON:-$REPO/wireguardrtc}"
PY="${PY:-$REPO/venv/bin/python3}"
FABRIC_SH="$HERE/fabric.sh"
STUN_STUB="$HERE/stun_stub.py"

if [[ -z "${PEERJS:-}" ]]; then
    if command -v peerjs >/dev/null 2>&1; then
        PEERJS=$(command -v peerjs)
    elif [[ -x "$HERE/node_modules/.bin/peerjs" ]]; then
        PEERJS="$HERE/node_modules/.bin/peerjs"
    else
        echo "error: peerjs binary not found" >&2
        exit 2
    fi
fi

[[ -x "$PY" ]]      || { echo "error: $PY not found" >&2; exit 2; }
[[ -x "$DAEMON" ]]  || { echo "error: $DAEMON not found" >&2; exit 2; }
[[ -x "$STUN_STUB" ]] || { echo "error: $STUN_STUB not found" >&2; exit 2; }

if [[ -z "${WGRTC_FABRIC_INSIDE:-}" ]]; then
    export PEERJS DAEMON PY STUN_STUB
    exec "$FABRIC_SH" "$0" "$@"
fi

source "$FABRIC_SH"

# ─── Topology ──────────────────────────────────────────────────────────────

fabric_create_host transit
fabric_create_host broker
fabric_create_host A
fabric_create_host B
fabric_create_host C

fabric_link transit broker  v-tb-t v-tb-b
fabric_link transit A       v-tA-t v-tA-A
fabric_link transit B       v-tB-t v-tB-B
fabric_link transit C       v-tC-t v-tC-C

fabric_exec_capture transit "
    ip link add br0 type bridge
    ip link set v-tb-t master br0
    ip link set v-tA-t master br0
    ip link set v-tB-t master br0
    ip link set v-tC-t master br0
    ip link set br0 up
    ip link set v-tb-t up
    ip link set v-tA-t up
    ip link set v-tB-t up
    ip link set v-tC-t up
" >/dev/null

fabric_exec_capture broker "ip addr add 192.168.99.10/24 dev v-tb-b && ip link set v-tb-b up" >/dev/null
fabric_exec_capture A      "ip addr add 192.168.99.20/24 dev v-tA-A && ip link set v-tA-A up" >/dev/null
fabric_exec_capture B      "ip addr add 192.168.99.30/24 dev v-tB-B && ip link set v-tB-B up" >/dev/null
fabric_exec_capture C      "ip addr add 192.168.99.40/24 dev v-tC-C && ip link set v-tC-C up" >/dev/null

# ─── Broker + STUN stub ────────────────────────────────────────────────────

echo "[cascade] starting PeerJS broker..."
fabric_exec broker "$PEERJS --port 9000 --key cascadetestkey > $FABRIC_TMP/broker.log 2>&1 &"
echo "[cascade] starting STUN stub..."
fabric_exec broker "python3 $STUN_STUB --bind 0.0.0.0 --port 3478 > $FABRIC_TMP/stun.log 2>&1 &"

for i in $(seq 1 30); do
    rc=$(fabric_exec_capture A "nc -z -w 1 192.168.99.10 9000 2>/dev/null ; echo \$?" 2>/dev/null | tr -d '[:space:]')
    [[ "$rc" == "0" ]] && break
    sleep 0.2
done

# ─── WireGuard interfaces ──────────────────────────────────────────────────

A_PRIV=$(wg genkey); A_PUB=$(echo "$A_PRIV" | wg pubkey)
B_PRIV=$(wg genkey); B_PUB=$(echo "$B_PRIV" | wg pubkey)
C_PRIV=$(wg genkey); C_PUB=$(echo "$C_PRIV" | wg pubkey)
SALT=$(head -c 32 /dev/urandom | base64)

# A: wg0=10.0.0.1, knows B; routes everything in /24 via wg0.
fabric_exec_capture A "
    ip link add wg0 type wireguard
    ip addr add 10.0.0.1/24 dev wg0
    wg set wg0 private-key <(echo '$A_PRIV') listen-port 51820 \
        peer '$B_PUB' allowed-ips 10.0.0.0/24 persistent-keepalive 25
    ip link set wg0 up
" >/dev/null

# B: wg0=10.0.0.2, knows A and C; IP-forwarding enabled.
fabric_exec_capture B "
    ip link add wg0 type wireguard
    ip addr add 10.0.0.2/24 dev wg0
    wg set wg0 private-key <(echo '$B_PRIV') listen-port 51820 \
        peer '$A_PUB' allowed-ips 10.0.0.1/32 persistent-keepalive 25 \
        peer '$C_PUB' allowed-ips 10.0.0.3/32 persistent-keepalive 25
    ip link set wg0 up
    sysctl -w net.ipv4.ip_forward=1
" >/dev/null

# C: wg0=10.0.0.3, knows B; routes everything in /24 via wg0.
fabric_exec_capture C "
    ip link add wg0 type wireguard
    ip addr add 10.0.0.3/24 dev wg0
    wg set wg0 private-key <(echo '$C_PRIV') listen-port 51820 \
        peer '$B_PUB' allowed-ips 10.0.0.0/24 persistent-keepalive 25
    ip link set wg0 up
" >/dev/null

# ─── Daemon configs ────────────────────────────────────────────────────────

mkdir -p \
    "$FABRIC_TMP/A-cfg/peers.d" \
    "$FABRIC_TMP/B-cfg/peers.d" \
    "$FABRIC_TMP/C-cfg/peers.d"

for d in A-cfg B-cfg C-cfg; do
    cat > "$FABRIC_TMP/$d/wireguardrtc.conf" <<EOF
[Global]
Salt = $SALT
PeerJsServer = ws://192.168.99.10:9000/peerjs
PeerJsKey = cascadetestkey

[Stun]
Servers = 192.168.99.10:3478
EOF
done

# A only knows B.
cat > "$FABRIC_TMP/A-cfg/peers.d/B.conf" <<EOF
[Peer]
PublicKey = $B_PUB
Mode = active
EOF

# B knows A and C.
cat > "$FABRIC_TMP/B-cfg/peers.d/A.conf" <<EOF
[Peer]
PublicKey = $A_PUB
Mode = active
EOF
cat > "$FABRIC_TMP/B-cfg/peers.d/C.conf" <<EOF
[Peer]
PublicKey = $C_PUB
Mode = active
EOF

# C only knows B.
cat > "$FABRIC_TMP/C-cfg/peers.d/B.conf" <<EOF
[Peer]
PublicKey = $B_PUB
Mode = active
EOF

# ─── Privsep helpers + daemons ─────────────────────────────────────────────

ORACLE="${ORACLE:-$REPO/wireguardrtc-key-oracle}"
RAW_HELPER="${RAW_HELPER:-$REPO/wireguardrtc-raw-helper}"
[[ -x "$ORACLE" ]] || { echo "error: $ORACLE not found" >&2; exit 2; }
[[ -x "$RAW_HELPER" ]] || { echo "error: $RAW_HELPER not found" >&2; exit 2; }

start_helpers() {
    local host="$1"
    fabric_exec "$host" "
        WIREGUARDRTC_KEY_ORACLE_SOCKET='$FABRIC_TMP/$host-oracle.sock' \
        '$PY' '$ORACLE' > '$FABRIC_TMP/$host-oracle.log' 2>&1 &
        WIREGUARDRTC_RAW_HELPER_SOCKET='$FABRIC_TMP/$host-raw.sock' \
        '$PY' '$RAW_HELPER' > '$FABRIC_TMP/$host-raw.log' 2>&1 &
    "
    for _i in $(seq 1 30); do
        [[ -S "$FABRIC_TMP/$host-oracle.sock" \
           && -S "$FABRIC_TMP/$host-raw.sock" ]] && return 0
        sleep 0.1
    done
    echo "[cascade] FAIL — privsep helpers for $host did not bring up sockets" >&2
    return 1
}

start_helpers A
start_helpers B
start_helpers C

start_daemon() {
    local host="$1"
    fabric_exec "$host" "
        WIREGUARDRTC_LOCK_FILE='$FABRIC_TMP/$host.lock' \
        WIREGUARDRTC_KEY_ORACLE_SOCKET='$FABRIC_TMP/$host-oracle.sock' \
        WIREGUARDRTC_RAW_HELPER_SOCKET='$FABRIC_TMP/$host-raw.sock' \
        '$PY' '$DAEMON' \
            --config '$FABRIC_TMP/$host-cfg/wireguardrtc.conf' \
            --peers-dir '$FABRIC_TMP/$host-cfg/peers.d' \
            --log-level INFO \
            > '$FABRIC_TMP/$host.log' 2>&1 &
    "
}

start_daemon A
start_daemon B
start_daemon C

# ─── Wait for all three peer handshakes on B ───────────────────────────────
# B is the central hub: it has handshakes to BOTH A and C.  We poll B's
# `wg show wg0 latest-handshakes` and require both lines to be non-zero
# before declaring the mesh ready.

echo "[cascade] waiting up to 90s for both handshakes on B..."
HANDSHAKES_OK=0
for i in $(seq 1 90); do
    sleep 1
    # B shows two peer lines; each is "<pubkey>\t<epoch>".  Strip pubkey
    # (column 1) and check that BOTH timestamps are positive.
    HS=$(fabric_exec_capture B "wg show wg0 latest-handshakes 2>/dev/null | awk '{print \$2}'" 2>/dev/null)
    # Map to space-separated, then count non-zero positive timestamps.
    OK_COUNT=$(echo "$HS" | awk 'NF{if ($1 ~ /^[0-9]+$/ && $1+0 > 0) c++} END{print c+0}')
    if [[ "$OK_COUNT" == "2" ]]; then
        echo "[cascade] both handshakes up at t+${i}s"
        HANDSHAKES_OK=1
        break
    fi
done

if [[ $HANDSHAKES_OK -ne 1 ]]; then
    echo "[cascade] FAIL — at least one handshake did not complete"
    for h in A B C; do
        echo "─── $h.log (tail) ───"
        fabric_exec_capture "$h" "tail -40 '$FABRIC_TMP/$h.log'" 2>&1
    done
    echo "─── broker.log (tail) ───"
    fabric_exec_capture broker "tail -40 '$FABRIC_TMP/broker.log'" 2>&1
    exit 1
fi

# ─── Cascade reachability test: C → A through B ────────────────────────────
# Use unprivileged ICMP (ping uses /proc/sys/net/ipv4/ping_group_range
# in a default unshare setup, but the fabric runs as uid 0 inside the
# user namespace so privileged ping works too).

echo "[cascade] testing C → A (10.0.0.1) reachability via B..."
PING_RC=$(fabric_exec_capture C "ping -c 3 -W 2 10.0.0.1 >/dev/null 2>&1; echo \$?" 2>/dev/null | tr -d '[:space:]')

if [[ "$PING_RC" != "0" ]]; then
    echo "[cascade] FAIL — C cannot reach A via B (ping rc=$PING_RC)"
    echo "─── C wg show ───"
    fabric_exec_capture C "wg show wg0" 2>&1
    echo "─── B wg show ───"
    fabric_exec_capture B "wg show wg0" 2>&1
    echo "─── A wg show ───"
    fabric_exec_capture A "wg show wg0" 2>&1
    exit 1
fi

echo "[cascade] PASS — C reached A (10.0.0.1) through B's transit"

# ─── Negative control: C → 10.0.0.99 (no such peer) must fail ──────────────
# B has no route to 10.0.0.99 and no peer with that AllowedIP, so packets
# should be dropped.  We expect ping to exit non-zero (timeout).

echo "[cascade] negative control: C → 10.0.0.99 should fail..."
NEG_RC=$(fabric_exec_capture C "ping -c 2 -W 2 10.0.0.99 >/dev/null 2>&1; echo \$?" 2>/dev/null | tr -d '[:space:]')

if [[ "$NEG_RC" == "0" ]]; then
    echo "[cascade] FAIL — ping to nonexistent peer 10.0.0.99 unexpectedly succeeded"
    exit 1
fi

echo "[cascade] PASS — negative control held (ping to 10.0.0.99 failed as expected)"
echo "[cascade] OVERALL PASS"
