#!/bin/bash
# _enroll_topology.sh — shared fabric setup for tests 10..15.
#
# Sourced from enrollment tests.  Sets up a 4-host fabric:
#   transit  L2 hub
#   broker   192.168.99.10  (PeerJS)
#   server   192.168.99.20  (wireguardrtc daemon w/ enrollment enabled)
#   client   192.168.99.30  (where reference enroll_client.py runs)
#
# Provides shell helpers for the enrolling tests:
#   _mint NAME             mint a token via --enroll-token, echo its URI
#   _run_daemon            start the daemon (background) inside `server`
#
# Required env (from the calling test):
#   FABRIC_SH, FABRIC_TMP, HERE, REPO, DAEMON, PY, PEERJS, CLIENT

# shellcheck disable=SC2154

# Privsep helper paths.  Defaults follow the in-tree layout; tests can
# override (REPO points at the github checkout root).
ORACLE="${ORACLE:-$REPO/wireguardrtc-key-oracle}"
RAW_HELPER="${RAW_HELPER:-$REPO/wireguardrtc-raw-helper}"

fabric_create_host transit
fabric_create_host broker
fabric_create_host server
fabric_create_host client
fabric_link transit broker  v-tb-t v-tb-b
fabric_link transit server  v-ts-t v-ts-s
fabric_link transit client  v-tc-t v-tc-c
fabric_exec_capture transit "
    ip link add br0 type bridge
    for i in v-tb-t v-ts-t v-tc-t; do
        ip link set \$i master br0
        ip link set \$i up
    done
    ip link set br0 up
" >/dev/null
fabric_exec_capture broker "ip addr add 192.168.99.10/24 dev v-tb-b && ip link set v-tb-b up" >/dev/null
fabric_exec_capture server "ip addr add 192.168.99.20/24 dev v-ts-s && ip link set v-ts-s up" >/dev/null
fabric_exec_capture client "ip addr add 192.168.99.30/24 dev v-tc-c && ip link set v-tc-c up" >/dev/null

fabric_exec broker "$PEERJS --port 9000 --key e2etestkey > $FABRIC_TMP/broker.log 2>&1 &"
for _i in $(seq 1 30); do
    rc=$(fabric_exec_capture client "nc -z -w 1 192.168.99.10 9000 2>/dev/null ; echo \$?" 2>/dev/null | tr -d '[:space:]')
    [[ "$rc" == "0" ]] && break
    sleep 0.2
done

SRV_PRIV=$(wg genkey); SRV_PUB=$(echo "$SRV_PRIV" | wg pubkey)
SALT=$(head -c 32 /dev/urandom | base64)
fabric_exec_capture server "
    ip link add wg0 type wireguard
    ip addr add 10.0.0.1/24 dev wg0
    wg set wg0 private-key <(echo '$SRV_PRIV') listen-port 51820
    ip link set wg0 up
" >/dev/null

cat > "$FABRIC_TMP/provision.sh" <<'EOF'
#!/bin/bash
set -euo pipefail
IFC="$1"; NAME="$2"; PK="$3"
STATE="$(dirname "$0")"
LOCK="$STATE/.provision.lock"; SLOT="$STATE/.next_slot"
exec 9<>"$LOCK"; flock 9
n=$(cat "$SLOT" 2>/dev/null || echo 2)
addr="10.0.0.$n/32"
echo $((n+1)) > "$SLOT"
wg set "$IFC" peer "$PK" allowed-ips "$addr"
EOF
chmod +x "$FABRIC_TMP/provision.sh"

mkdir -p "$FABRIC_TMP/server-cfg/peers.d" "$FABRIC_TMP/state"
cat > "$FABRIC_TMP/server-cfg/wireguardrtc.conf" <<EOF
[Global]
Salt = $SALT
PeerJsServer = ws://192.168.99.10:9000/peerjs
PeerJsKey = e2etestkey
PublicIp = 192.168.99.20

[Stun]
Servers =

[Enrollment]
Enabled = yes
ProvisionScript = ${ENROLL_PROVISION_SCRIPT:-$FABRIC_TMP/provision.sh}
StateDir = $FABRIC_TMP/state
EOF

# Helper: mint a token and echo only its URI (stderr is the human banner).
_mint() {
    local name="$1"
    local extra="${2:-}"   # e.g., "--expires 60"
    local out
    out=$(fabric_exec_capture server "
        WIREGUARDRTC_LOCK_FILE='$FABRIC_TMP/server.lock' \
        '$PY' '$DAEMON' \
            --config '$FABRIC_TMP/server-cfg/wireguardrtc.conf' \
            --peers-dir '$FABRIC_TMP/server-cfg/peers.d' \
            --enroll-token $name $extra
    " 2>&1)
    echo "$out" | grep -o 'wgrtc-enroll://[^[:space:]]*' | head -1
}

# Helper: start the privilege-separated key oracle in the server ns.
# The oracle holds the wg0 private key so the daemon doesn't have to;
# without it the daemon fails to start in this version of the package.
# Idempotent — safe to call twice.
_start_oracle() {
    [[ -S "$FABRIC_TMP/oracle.sock" ]] && return 0
    fabric_exec server "
        WIREGUARDRTC_KEY_ORACLE_SOCKET='$FABRIC_TMP/oracle.sock' \
        '$PY' '$ORACLE' > '$FABRIC_TMP/oracle.log' 2>&1 &
    "
    for _i in $(seq 1 30); do
        [[ -S "$FABRIC_TMP/oracle.sock" ]] && return 0
        sleep 0.1
    done
    echo "key-oracle did not bring up its socket; log:" >&2
    cat "$FABRIC_TMP/oracle.log" >&2
    return 1
}

# Helper: start the raw-socket helper in the server ns.  Holds
# CAP_NET_RAW so the daemon doesn't have to; the daemon won't start
# without it either.
_start_raw_helper() {
    [[ -S "$FABRIC_TMP/raw.sock" ]] && return 0
    fabric_exec server "
        WIREGUARDRTC_RAW_HELPER_SOCKET='$FABRIC_TMP/raw.sock' \
        '$PY' '$RAW_HELPER' > '$FABRIC_TMP/raw.log' 2>&1 &
    "
    for _i in $(seq 1 30); do
        [[ -S "$FABRIC_TMP/raw.sock" ]] && return 0
        sleep 0.1
    done
    echo "raw-helper did not bring up its socket; log:" >&2
    cat "$FABRIC_TMP/raw.log" >&2
    return 1
}

# Helper: start the daemon as a background process inside `server`.
# Both privsep helpers are started first; the daemon Requires= them
# in production via systemd, and refuses to run without them in the
# fabric here for the same reason.
_run_daemon() {
    _start_oracle
    _start_raw_helper
    fabric_exec server "
        env WIREGUARDRTC_LOCK_FILE='$FABRIC_TMP/server.lock' \
            WIREGUARDRTC_KEY_ORACLE_SOCKET='$FABRIC_TMP/oracle.sock' \
            WIREGUARDRTC_RAW_HELPER_SOCKET='$FABRIC_TMP/raw.sock' \
        '$PY' '$DAEMON' \
            --config '$FABRIC_TMP/server-cfg/wireguardrtc.conf' \
            --peers-dir '$FABRIC_TMP/server-cfg/peers.d' \
            --log-level INFO > '$FABRIC_TMP/server.log' 2>&1 &
    "
    sleep 2
}
