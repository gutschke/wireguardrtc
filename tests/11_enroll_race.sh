#!/bin/bash
# 11_enroll_race.sh — single-use token enforcement.
#
# Two attackers race for the same token.  First valid ENROLL wins;
# all subsequent attempts get TOKEN_USED.  Both attackers can decrypt
# their respective server responses (so they each KNOW they failed —
# this is the user-noticing property that PLAN.md §4.4.3 calls for).
#
# Same env / requirements as 10_enroll_basic.sh.

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

fabric_create_host transit
fabric_create_host broker
fabric_create_host server
fabric_create_host alice    # legitimate client
fabric_create_host mallory  # attacker who scanned the same QR
fabric_link transit broker  v-tb-t v-tb-b
fabric_link transit server  v-ts-t v-ts-s
fabric_link transit alice   v-ta-t v-ta-a
fabric_link transit mallory v-tm-t v-tm-m
fabric_exec_capture transit "
    ip link add br0 type bridge
    for i in v-tb-t v-ts-t v-ta-t v-tm-t; do
        ip link set \$i master br0
        ip link set \$i up
    done
    ip link set br0 up
" >/dev/null
fabric_exec_capture broker  "ip addr add 192.168.99.10/24 dev v-tb-b && ip link set v-tb-b up" >/dev/null
fabric_exec_capture server  "ip addr add 192.168.99.20/24 dev v-ts-s && ip link set v-ts-s up" >/dev/null
fabric_exec_capture alice   "ip addr add 192.168.99.30/24 dev v-ta-a && ip link set v-ta-a up" >/dev/null
fabric_exec_capture mallory "ip addr add 192.168.99.40/24 dev v-tm-m && ip link set v-tm-m up" >/dev/null

echo "[11] starting broker..."
fabric_exec broker "$PEERJS --port 9000 --key e2etestkey > $FABRIC_TMP/broker.log 2>&1 &"
for i in $(seq 1 30); do
    rc=$(fabric_exec_capture alice "nc -z -w 1 192.168.99.10 9000 2>/dev/null ; echo \$?" 2>/dev/null | tr -d '[:space:]')
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
ProvisionScript = $FABRIC_TMP/provision.sh
StateDir = $FABRIC_TMP/state
EOF

# Mint ONE token — both alice and mallory will try to use it.
echo "[11] minting token..."
mint_out=$(fabric_exec_capture server "
    WIREGUARDRTC_LOCK_FILE='$FABRIC_TMP/server.lock' \
    '$PY' '$DAEMON' \
        --config '$FABRIC_TMP/server-cfg/wireguardrtc.conf' \
        --peers-dir '$FABRIC_TMP/server-cfg/peers.d' \
        --enroll-token testclient
" 2>&1)
URI=$(echo "$mint_out" | grep -o 'wgrtc-enroll://[^[:space:]]*' | head -1)
[[ -n "$URI" ]] || { echo "[11] FAIL — no URI minted"; exit 1; }

# Privsep helpers (key oracle + raw helper) — see test 10 for rationale.
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

# Start the daemon (talks to the helpers via the env-supplied sockets)
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

# Race: both try at once.  Each writes its result to a per-host file.
echo "[11] launching alice and mallory in parallel..."
fabric_exec alice   "'$PY' '$CLIENT' --json '$URI' --device alice   > '$FABRIC_TMP/alice.json'   2>&1 &"
fabric_exec mallory "'$PY' '$CLIENT' --json '$URI' --device mallory > '$FABRIC_TMP/mallory.json' 2>&1 &"

# Wait for both to finish.
echo "[11] waiting for both clients to finish..."
for i in $(seq 1 40); do
    sleep 0.5
    a_done=$(fabric_exec_capture alice "[[ -e '$FABRIC_TMP/alice.json' ]] && grep -q '\"kind\"' '$FABRIC_TMP/alice.json' && echo Y || echo N" 2>/dev/null | tr -d '[:space:]')
    m_done=$(fabric_exec_capture mallory "[[ -e '$FABRIC_TMP/mallory.json' ]] && grep -q '\"kind\"' '$FABRIC_TMP/mallory.json' && echo Y || echo N" 2>/dev/null | tr -d '[:space:]')
    if [[ "$a_done" == "Y" && "$m_done" == "Y" ]]; then break; fi
done

A_OUT=$(fabric_exec_capture alice   "cat '$FABRIC_TMP/alice.json'"   2>/dev/null)
M_OUT=$(fabric_exec_capture mallory "cat '$FABRIC_TMP/mallory.json'" 2>/dev/null)
echo "[11] alice.json:"; echo "$A_OUT" | sed 's/^/    /' | head -15
echo "[11] mallory.json:"; echo "$M_OUT" | sed 's/^/    /' | head -15

A_KIND=$(echo "$A_OUT" | $PY -c "import json,sys; print(json.load(sys.stdin).get('kind',''))" 2>/dev/null || echo "")
M_KIND=$(echo "$M_OUT" | $PY -c "import json,sys; print(json.load(sys.stdin).get('kind',''))" 2>/dev/null || echo "")
A_CODE=$(echo "$A_OUT" | $PY -c "import json,sys; print(json.load(sys.stdin)['plaintext'].get('code',''))" 2>/dev/null || echo "")
M_CODE=$(echo "$M_OUT" | $PY -c "import json,sys; print(json.load(sys.stdin)['plaintext'].get('code',''))" 2>/dev/null || echo "")

echo "[11] alice:   kind=$A_KIND code=$A_CODE"
echo "[11] mallory: kind=$M_KIND code=$M_CODE"

# Exactly ONE of the two must have succeeded; the other must be TOKEN_USED.
ok_count=0
[[ "$A_KIND" == "enroll_ok" ]] && ok_count=$((ok_count+1))
[[ "$M_KIND" == "enroll_ok" ]] && ok_count=$((ok_count+1))
used_count=0
[[ "$A_CODE" == "TOKEN_USED" ]] && used_count=$((used_count+1))
[[ "$M_CODE" == "TOKEN_USED" ]] && used_count=$((used_count+1))

if [[ $ok_count -eq 1 && $used_count -eq 1 ]]; then
    echo "[11] PASS — single-use enforced (one winner, one TOKEN_USED rejection)"
    exit 0
fi
echo "[11] FAIL — got $ok_count enroll_ok and $used_count TOKEN_USED (expected 1+1)"
echo "─── server.log ───"; fabric_exec_capture server "tail -40 '$FABRIC_TMP/server.log'"
exit 1
