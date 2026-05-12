#!/bin/bash
# 10_enroll_basic.sh — happy-path auto-enrollment.
#
#   1. Admin mints an enrollment token via `wireguardrtc --enroll-token`.
#   2. Reference client parses the resulting URI and runs ENROLL.
#   3. Server processes the request, calls ProvisionScript, returns
#      ENROLL_OK with the allocated WG config.
#   4. Verify:
#        - client received ENROLL_OK (not ENROLL_ERR)
#        - client decrypted the response successfully
#        - response contains a valid /32 address inside the configured pool
#        - server's wg0 now has the client as a peer with that allowed-ip
#        - the pending-tokens file shows the token consumed
#
# Same env / requirements as 08_fabric_e2e.sh: PEERJS, PY, DAEMON.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
DAEMON="${DAEMON:-$REPO/wireguardrtc}"
PY="${PY:-$REPO/venv/bin/python3}"
FABRIC_SH="$HERE/fabric.sh"
CLIENT="$HERE/enroll_client.py"

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
[[ -x "$PY" ]]      || { echo "error: $PY not found" >&2; exit 2; }
[[ -x "$DAEMON" ]]  || { echo "error: $DAEMON not found" >&2; exit 2; }
[[ -x "$CLIENT" ]]  || { echo "error: $CLIENT not found" >&2; exit 2; }

if [[ -z "${WGRTC_FABRIC_INSIDE:-}" ]]; then
    export PEERJS DAEMON PY
    exec "$FABRIC_SH" "$0" "$@"
fi

source "$FABRIC_SH"

# ─── Topology ──────────────────────────────────────────────────────────────
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

echo "[10] starting PeerJS broker..."
fabric_exec broker "$PEERJS --port 9000 --key e2etestkey > $FABRIC_TMP/broker.log 2>&1 &"
for i in $(seq 1 30); do
    rc=$(fabric_exec_capture client "nc -z -w 1 192.168.99.10 9000 2>/dev/null ; echo \$?" 2>/dev/null | tr -d '[:space:]')
    [[ "$rc" == "0" ]] && break
    sleep 0.2
done

# ─── Server's WireGuard interface (no peers yet — they'll be added by enroll) ─
SRV_PRIV=$(wg genkey); SRV_PUB=$(echo "$SRV_PRIV" | wg pubkey)
SALT=$(head -c 32 /dev/urandom | base64)
fabric_exec_capture server "
    ip link add wg0 type wireguard
    ip addr add 10.0.0.1/24 dev wg0
    wg set wg0 private-key <(echo '$SRV_PRIV') listen-port 51820
    ip link set wg0 up
" >/dev/null

# ─── Provisioning script that the daemon will invoke ─────────────────────
# Simple counter-based allocator: reads $FABRIC_TMP/.next_slot, writes a
# fresh /32 inside the 10.0.0.0/24 pool, runs `wg set` to add the peer.
mkdir -p "$FABRIC_TMP"
cat > "$FABRIC_TMP/provision.sh" <<'PROVISIONEOF'
#!/bin/bash
# Test ProvisionScript.  Args: IFACE NAME PUBKEY_BASE64
set -euo pipefail
IFC="$1"; NAME="$2"; PK="$3"
STATE_DIR="$(dirname "$0")"
LOCK="$STATE_DIR/.provision.lock"
SLOTFILE="$STATE_DIR/.next_slot"
exec 9<>"$LOCK"; flock 9
slot=$(cat "$SLOTFILE" 2>/dev/null || echo 2)
addr="10.0.0.$slot/32"
echo $((slot + 1)) > "$SLOTFILE"
wg set "$IFC" peer "$PK" allowed-ips "$addr" persistent-keepalive 25
echo "$NAME -> $PK -> $addr" >> "$STATE_DIR/.provision.log"
exit 0
PROVISIONEOF
chmod +x "$FABRIC_TMP/provision.sh"

# ─── Daemon configuration on the server ────────────────────────────────────
mkdir -p "$FABRIC_TMP/server-cfg/peers.d"
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
ProvisionScript = $FABRIC_TMP/provision.sh
StateDir = $FABRIC_TMP/state
EOF
mkdir -p "$FABRIC_TMP/state"

# ─── Mint an enrollment token via --enroll-token ───────────────────────────
echo "[10] minting enrollment token..."
set +e
mint_out=$(fabric_exec_capture server "
    WIREGUARDRTC_LOCK_FILE='$FABRIC_TMP/server.lock' \
    '$PY' '$DAEMON' \
        --config '$FABRIC_TMP/server-cfg/wireguardrtc.conf' \
        --peers-dir '$FABRIC_TMP/server-cfg/peers.d' \
        --enroll-token testclient \
        --expires 600
" 2>&1)
mint_rc=$?
set -uo pipefail
echo "[10] mint rc=$mint_rc, output:"
echo "$mint_out" | sed 's/^/    /'
URI=$(echo "$mint_out" | grep -o 'wgrtc-enroll://[^[:space:]]*' | head -1)
if [[ -z "$URI" ]]; then
    echo "[10] FAIL — --enroll-token didn't print a URI"
    exit 1
fi
echo "[10] got URI (truncated): ${URI:0:80}..."

# ─── Privsep helpers + daemon ──────────────────────────────────────────────
# The daemon holds no Linux capabilities and refuses to start unless
# it can reach the key oracle (CAP_NET_ADMIN) and the raw helper
# (CAP_NET_RAW) on Unix sockets.  Spawn both inside the same `server`
# host before launching the daemon.
ORACLE="${ORACLE:-$REPO/wireguardrtc-key-oracle}"
RAW_HELPER="${RAW_HELPER:-$REPO/wireguardrtc-raw-helper}"
fabric_exec server "
    WIREGUARDRTC_KEY_ORACLE_SOCKET='$FABRIC_TMP/oracle.sock' \
    '$PY' '$ORACLE' > '$FABRIC_TMP/oracle.log' 2>&1 &
    WIREGUARDRTC_RAW_HELPER_SOCKET='$FABRIC_TMP/raw.sock' \
    '$PY' '$RAW_HELPER' > '$FABRIC_TMP/raw.log' 2>&1 &
"
for _ in $(seq 1 30); do
    [[ -S "$FABRIC_TMP/oracle.sock" && -S "$FABRIC_TMP/raw.sock" ]] && break
    sleep 0.1
done

fabric_exec server "
    env WIREGUARDRTC_LOCK_FILE='$FABRIC_TMP/server.lock' \
        WIREGUARDRTC_KEY_ORACLE_SOCKET='$FABRIC_TMP/oracle.sock' \
        WIREGUARDRTC_RAW_HELPER_SOCKET='$FABRIC_TMP/raw.sock' \
    '$PY' '$DAEMON' \
        --config '$FABRIC_TMP/server-cfg/wireguardrtc.conf' \
        --peers-dir '$FABRIC_TMP/server-cfg/peers.d' \
        --log-level INFO \
        > '$FABRIC_TMP/server.log' 2>&1 &
"
sleep 2  # let it connect to broker + helpers

# ─── Run the reference enrollment client ───────────────────────────────────
echo "[10] running reference enrollment client..."
client_out=$(fabric_exec_capture client "
    '$PY' '$CLIENT' --json '$URI' --timeout 30 2>&1
")
client_rc=$?
echo "[10] client output:"; echo "$client_out" | sed 's/^/    /'

if [[ $client_rc -ne 0 ]]; then
    echo "[10] FAIL — client exit $client_rc"
    echo "─── server.log ───"; fabric_exec_capture server "tail -40 '$FABRIC_TMP/server.log'"
    exit 1
fi

# Parse JSON output to extract the address
ADDR=$(echo "$client_out" | $PY -c "import json, sys; d=json.load(sys.stdin); print(d['plaintext'].get('address',''))")
if [[ ! "$ADDR" =~ ^10\.0\.0\.[0-9]+/32$ ]]; then
    echo "[10] FAIL — bad address in ENROLL_OK: $ADDR"
    exit 1
fi
echo "[10] ENROLL_OK with address=$ADDR"

# Verify server-side: the client's pubkey is now a WG peer
CLIENT_PUB=$(echo "$client_out" | $PY -c "import json, sys; print(json.load(sys.stdin)['client_pub_b64'])")
peer_check=$(fabric_exec_capture server "wg show wg0 allowed-ips | grep -F '$CLIENT_PUB' || echo MISSING")
if [[ "$peer_check" =~ MISSING ]]; then
    echo "[10] FAIL — client pubkey not added to server's wg0"
    exit 1
fi
echo "[10] server has client as peer: $peer_check"

# Verify token storage shows it consumed
if [[ -f "$FABRIC_TMP/state/pending-tokens.json" ]]; then
    used=$(fabric_exec_capture server "$PY -c \"
import json
with open('$FABRIC_TMP/state/pending-tokens.json') as f:
    data = json.load(f)
for t in data.get('tokens', []):
    if t.get('used'):
        print('USED:', t.get('name_hint'))
        break
else:
    print('UNUSED')
\"")
    echo "[10] token state: $used"
    if [[ "$used" =~ ^USED ]]; then
        echo "[10] PASS — happy-path enrollment works end-to-end"
        exit 0
    fi
fi
echo "[10] FAIL — token not marked used after successful enrollment"
exit 1
