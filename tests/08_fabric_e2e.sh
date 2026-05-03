#!/bin/bash
# 08_fabric_e2e.sh — end-to-end fabric validation.
#
# Brings up the test fabric (broker + 2 daemons + STUN stub) and verifies
# that two wireguardrtc instances complete a WireGuard handshake through
# PeerJS signalling.  No NAT topology — exercises the protocol round-trip
# only; NAT-traversal validation is a follow-up scenario.
#
# Requirements (all paths relative to the repo root):
#   - venv/                          Python venv with websockets + pynacl
#   - tests/fabric.sh                The fabric harness
#   - tests/stun_stub.py             Minimal STUN responder
#   - PeerJS broker available on PATH or under tests/peerjs/, see USAGE.
#
# USAGE:
#   ./tests/08_fabric_e2e.sh                       # auto-detect peerjs
#   PEERJS=/path/to/peerjs ./tests/08_fabric_e2e.sh
#
# This script must be invoked OUTSIDE the fabric.  It re-execs itself
# inside the fabric automatically.

set -uo pipefail

# Locate paths relative to this script.
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
DAEMON="${DAEMON:-$REPO/wireguardrtc}"
PY="${PY:-$REPO/venv/bin/python3}"
FABRIC_SH="$HERE/fabric.sh"
STUN_STUB="$HERE/stun_stub.py"

# Auto-detect peerjs binary (the modern `peer` npm package's CLI).
# Search order:
#   1. $PEERJS environment variable
#   2. peerjs on PATH
#   3. $REPO/tests/node_modules/.bin/peerjs  (local: cd tests && npm install peer)
if [[ -z "${PEERJS:-}" ]]; then
    if command -v peerjs >/dev/null 2>&1; then
        PEERJS=$(command -v peerjs)
    elif [[ -x "$HERE/node_modules/.bin/peerjs" ]]; then
        PEERJS="$HERE/node_modules/.bin/peerjs"
    else
        echo "error: peerjs binary not found" >&2
        echo "       Install one of:" >&2
        echo "         (global)   npm install -g peer" >&2
        echo "         (local)    cd $HERE && npm install peer" >&2
        echo "       Or set \$PEERJS to an existing peerjs binary." >&2
        exit 2
    fi
fi

[[ -x "$PY" ]]      || { echo "error: $PY not found (run: python3 -m venv venv && venv/bin/pip install websockets pynacl)" >&2; exit 2; }
[[ -x "$DAEMON" ]]  || { echo "error: $DAEMON not found" >&2; exit 2; }
[[ -x "$STUN_STUB" ]] || { echo "error: $STUN_STUB not found" >&2; exit 2; }

# Re-exec inside the fabric.
if [[ -z "${WGRTC_FABRIC_INSIDE:-}" ]]; then
    export PEERJS DAEMON PY STUN_STUB
    exec "$FABRIC_SH" "$0" "$@"
fi

source "$FABRIC_SH"

# ─── Topology ──────────────────────────────────────────────────────────────
# transit  ── L2 hub for broker, server, client
# broker   192.168.99.10  (PeerJS broker + STUN stub)
# server   192.168.99.20  (wireguardrtc daemon)
# client   192.168.99.30  (wireguardrtc daemon)

fabric_create_host transit
fabric_create_host broker
fabric_create_host server
fabric_create_host client

fabric_link transit broker  v-tb-t v-tb-b
fabric_link transit server  v-ts-t v-ts-s
fabric_link transit client  v-tc-t v-tc-c

fabric_exec_capture transit "
    ip link add br0 type bridge
    ip link set v-tb-t master br0
    ip link set v-ts-t master br0
    ip link set v-tc-t master br0
    ip link set br0 up
    ip link set v-tb-t up
    ip link set v-ts-t up
    ip link set v-tc-t up
" >/dev/null

fabric_exec_capture broker "ip addr add 192.168.99.10/24 dev v-tb-b && ip link set v-tb-b up" >/dev/null
fabric_exec_capture server "ip addr add 192.168.99.20/24 dev v-ts-s && ip link set v-ts-s up" >/dev/null
fabric_exec_capture client "ip addr add 192.168.99.30/24 dev v-tc-c && ip link set v-tc-c up" >/dev/null

# ─── Broker + STUN stub ────────────────────────────────────────────────────

echo "[e2e] starting PeerJS broker..."
fabric_exec broker "$PEERJS --port 9000 --key e2etestkey > $FABRIC_TMP/broker.log 2>&1 &"
echo "[e2e] starting STUN stub..."
fabric_exec broker "python3 $STUN_STUB --bind 0.0.0.0 --port 3478 > $FABRIC_TMP/stun.log 2>&1 &"

# Wait for broker to be listening.
for i in $(seq 1 30); do
    rc=$(fabric_exec_capture client "nc -z -w 1 192.168.99.10 9000 2>/dev/null ; echo \$?" 2>/dev/null | tr -d '[:space:]')
    [[ "$rc" == "0" ]] && break
    sleep 0.2
done

# ─── WireGuard interfaces ──────────────────────────────────────────────────

SRV_PRIV=$(wg genkey)
SRV_PUB=$(echo "$SRV_PRIV" | wg pubkey)
CLI_PRIV=$(wg genkey)
CLI_PUB=$(echo "$CLI_PRIV" | wg pubkey)
SALT=$(head -c 32 /dev/urandom | base64)

fabric_exec_capture server "
    ip link add wg0 type wireguard
    ip addr add 10.0.0.1/24 dev wg0
    wg set wg0 private-key <(echo '$SRV_PRIV') listen-port 51820 \
        peer '$CLI_PUB' allowed-ips 10.0.0.2/32 persistent-keepalive 25
    ip link set wg0 up
" >/dev/null

fabric_exec_capture client "
    ip link add wg0 type wireguard
    ip addr add 10.0.0.2/24 dev wg0
    wg set wg0 private-key <(echo '$CLI_PRIV') listen-port 51820 \
        peer '$SRV_PUB' allowed-ips 10.0.0.1/32 persistent-keepalive 25
    ip link set wg0 up
" >/dev/null

# ─── Daemon configs ────────────────────────────────────────────────────────

mkdir -p "$FABRIC_TMP/server-cfg/peers.d" "$FABRIC_TMP/client-cfg/peers.d"
for d in server-cfg client-cfg; do
    cat > "$FABRIC_TMP/$d/wireguardrtc.conf" <<EOF
[Global]
Salt = $SALT
PeerJsServer = ws://192.168.99.10:9000/peerjs
PeerJsKey = e2etestkey

[Stun]
Servers = 192.168.99.10:3478
EOF
done
cat > "$FABRIC_TMP/server-cfg/peers.d/client.conf" <<EOF
[Peer]
PublicKey = $CLI_PUB
Mode = active
EOF
cat > "$FABRIC_TMP/client-cfg/peers.d/server.conf" <<EOF
[Peer]
PublicKey = $SRV_PUB
Mode = active
EOF

# ─── Start privsep helpers + daemons ────────────────────────────────────────
# After the privsep refactors the daemon holds NO Linux capabilities and
# requires both the key oracle (CAP_NET_ADMIN) and the raw helper
# (CAP_NET_RAW) to be reachable on Unix sockets before it will start.
# Each daemon-host gets its own pair.
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
    echo "[e2e] FAIL — privsep helpers for $host did not bring up sockets" >&2
    return 1
}

start_helpers server
start_helpers client

fabric_exec server "
    WIREGUARDRTC_LOCK_FILE='$FABRIC_TMP/server.lock' \
    WIREGUARDRTC_KEY_ORACLE_SOCKET='$FABRIC_TMP/server-oracle.sock' \
    WIREGUARDRTC_RAW_HELPER_SOCKET='$FABRIC_TMP/server-raw.sock' \
    '$PY' '$DAEMON' \
        --config '$FABRIC_TMP/server-cfg/wireguardrtc.conf' \
        --peers-dir '$FABRIC_TMP/server-cfg/peers.d' \
        --log-level INFO \
        > '$FABRIC_TMP/server.log' 2>&1 &
"
fabric_exec client "
    WIREGUARDRTC_LOCK_FILE='$FABRIC_TMP/client.lock' \
    WIREGUARDRTC_KEY_ORACLE_SOCKET='$FABRIC_TMP/client-oracle.sock' \
    WIREGUARDRTC_RAW_HELPER_SOCKET='$FABRIC_TMP/client-raw.sock' \
    '$PY' '$DAEMON' \
        --config '$FABRIC_TMP/client-cfg/wireguardrtc.conf' \
        --peers-dir '$FABRIC_TMP/client-cfg/peers.d' \
        --log-level INFO \
        > '$FABRIC_TMP/client.log' 2>&1 &
"

echo "[e2e] waiting up to 60s for handshake..."
HANDSHAKE_OK=0
for i in $(seq 1 60); do
    sleep 1
    SRV_HS=$(fabric_exec_capture server "wg show wg0 latest-handshakes 2>/dev/null | awk '{print \$2}'" 2>/dev/null | tr -d '[:space:]')
    CLI_HS=$(fabric_exec_capture client "wg show wg0 latest-handshakes 2>/dev/null | awk '{print \$2}'" 2>/dev/null | tr -d '[:space:]')
    if [[ "$SRV_HS" =~ ^[0-9]+$ ]] && (( SRV_HS > 0 )) \
        && [[ "$CLI_HS" =~ ^[0-9]+$ ]] && (( CLI_HS > 0 )); then
        echo "[e2e] handshake established at t+${i}s"
        HANDSHAKE_OK=1
        break
    fi
done

if [[ $HANDSHAKE_OK -ne 1 ]]; then
    echo "[e2e] FAIL — no handshake within timeout"
    echo "─── server.log ───"; fabric_exec_capture server "tail -40 '$FABRIC_TMP/server.log'" 2>&1
    echo "─── client.log ───"; fabric_exec_capture client "tail -40 '$FABRIC_TMP/client.log'" 2>&1
    echo "─── broker.log ───"; fabric_exec_capture broker "tail -40 '$FABRIC_TMP/broker.log'" 2>&1
    exit 1
fi

echo "[e2e] PASS"
