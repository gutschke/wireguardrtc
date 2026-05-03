#!/bin/bash
# 09_publicip.sh — verify [Global] PublicIp = X.Y.Z.W skips STUN entirely.
#
# Same topology as 08, but [Stun] Servers = is empty and PublicIp is set
# to each host's local fabric IP.  The fact that the handshake completes
# without a STUN server running anywhere proves that PublicIp short-
# circuits the STUN code path.
#
# Same env / requirements as 08_fabric_e2e.sh.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
DAEMON="${DAEMON:-$REPO/wireguardrtc}"
PY="${PY:-$REPO/venv/bin/python3}"
FABRIC_SH="$HERE/fabric.sh"

if [[ -z "${PEERJS:-}" ]]; then
    if command -v peerjs >/dev/null 2>&1; then
        PEERJS=$(command -v peerjs)
    elif [[ -x "$HERE/node_modules/.bin/peerjs" ]]; then
        PEERJS="$HERE/node_modules/.bin/peerjs"
    else
        echo "error: peerjs not found (npm install -g peer)" >&2
        exit 2
    fi
fi
[[ -x "$PY" ]]     || { echo "error: $PY not found" >&2; exit 2; }
[[ -x "$DAEMON" ]] || { echo "error: $DAEMON not found" >&2; exit 2; }

if [[ -z "${WGRTC_FABRIC_INSIDE:-}" ]]; then
    export PEERJS DAEMON PY
    exec "$FABRIC_SH" "$0" "$@"
fi

source "$FABRIC_SH"

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

echo "[publicip] starting PeerJS broker (NO STUN stub on purpose)..."
fabric_exec broker "$PEERJS --port 9000 --key e2etestkey > $FABRIC_TMP/broker.log 2>&1 &"
for i in $(seq 1 30); do
    rc=$(fabric_exec_capture client "nc -z -w 1 192.168.99.10 9000 2>/dev/null ; echo \$?" 2>/dev/null | tr -d '[:space:]')
    [[ "$rc" == "0" ]] && break
    sleep 0.2
done

SRV_PRIV=$(wg genkey); SRV_PUB=$(echo "$SRV_PRIV" | wg pubkey)
CLI_PRIV=$(wg genkey); CLI_PUB=$(echo "$CLI_PRIV" | wg pubkey)
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

mkdir -p "$FABRIC_TMP/server-cfg/peers.d" "$FABRIC_TMP/client-cfg/peers.d"
cat > "$FABRIC_TMP/server-cfg/wireguardrtc.conf" <<EOF
[Global]
Salt = $SALT
PeerJsServer = ws://192.168.99.10:9000/peerjs
PeerJsKey = e2etestkey
PublicIp = 192.168.99.20

[Stun]
Servers =
EOF
cat > "$FABRIC_TMP/client-cfg/wireguardrtc.conf" <<EOF
[Global]
Salt = $SALT
PeerJsServer = ws://192.168.99.10:9000/peerjs
PeerJsKey = e2etestkey
PublicIp = 192.168.99.30

[Stun]
Servers =
EOF
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

# Privsep helpers (key oracle + raw-socket helper) per daemon host —
# see tests/08_fabric_e2e.sh for the rationale.
ORACLE="${ORACLE:-$REPO/wireguardrtc-key-oracle}"
RAW_HELPER="${RAW_HELPER:-$REPO/wireguardrtc-raw-helper}"
[[ -x "$ORACLE" && -x "$RAW_HELPER" ]] || \
    { echo "error: privsep helpers not found ($ORACLE / $RAW_HELPER)" >&2; exit 2; }

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
    return 1
}
start_helpers server || { echo "[publicip] FAIL — server helpers" >&2; exit 1; }
start_helpers client || { echo "[publicip] FAIL — client helpers" >&2; exit 1; }

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

echo "[publicip] waiting up to 30s for handshake..."
for i in $(seq 1 30); do
    sleep 1
    SRV_HS=$(fabric_exec_capture server "wg show wg0 latest-handshakes 2>/dev/null | awk '{print \$2}'" 2>/dev/null | tr -d '[:space:]')
    CLI_HS=$(fabric_exec_capture client "wg show wg0 latest-handshakes 2>/dev/null | awk '{print \$2}'" 2>/dev/null | tr -d '[:space:]')
    if [[ "$SRV_HS" =~ ^[0-9]+$ ]] && (( SRV_HS > 0 )) \
        && [[ "$CLI_HS" =~ ^[0-9]+$ ]] && (( CLI_HS > 0 )); then
        echo "[publicip] handshake at t+${i}s"
        # Confirm STUN was actually skipped
        if fabric_exec_capture server "grep -q 'configured override' '$FABRIC_TMP/server.log'" 2>/dev/null; then
            echo "[publicip] PASS — STUN skipped via PublicIp override"
            exit 0
        else
            echo "[publicip] FAIL — handshake worked but no 'configured override' log line"
            exit 1
        fi
    fi
done
echo "[publicip] FAIL — no handshake within 30s"
echo "─── server.log ───"; fabric_exec_capture server "tail -30 '$FABRIC_TMP/server.log'"
exit 1
