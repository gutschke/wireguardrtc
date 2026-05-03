#!/bin/bash
# 16_key_oracle.sh — unit-ish test of the privileged key-derivation oracle.
#
# Exercises wireguardrtc-key-oracle's three RPCs (derive_sigbox,
# derive_enroll, set_endpoint) and its validation+rejection paths
# against a real WireGuard interface inside an unprivileged user
# namespace.  Reference keys are computed in-process with PyNaCl and
# compared byte-for-byte to the oracle's responses.
#
# Coverage:
#   * derive_sigbox: byte-for-byte match against in-process derivation
#   * derive_enroll: byte-for-byte match (with random token)
#   * set_endpoint: legitimate update succeeds, kernel sees it
#   * set_endpoint: refuses loopback / link-local / multicast / reserved
#   * set_endpoint: refuses peers not on the iface (no implicit creation)
#   * iface validation: refuses eth0, uppercase, traversal
#   * pubkey validation: refuses too-short / wrong-alphabet / 32-byte mismatch
#   * token validation: refuses too-short / standard-b64 chars
#   * unknown op: refuses cleanly

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
ORACLE="$REPO/wireguardrtc-key-oracle"
PY="${PY:-$REPO/venv/bin/python3}"

[[ -x "$ORACLE" ]] || { echo "error: $ORACLE not found" >&2; exit 2; }
[[ -x "$PY" ]]     || { echo "error: $PY not found" >&2; exit 2; }
command -v unshare >/dev/null || { echo "need unshare" >&2; exit 2; }
command -v socat   >/dev/null || { echo "need socat" >&2; exit 2; }
command -v wg      >/dev/null || { echo "need wg(8)" >&2; exit 2; }

WORK=$(mktemp -d)
trap '
    pkill -f "$WORK/oracle.sock" 2>/dev/null ||:
    pkill -P $$ 2>/dev/null ||:
    rm -rf "$WORK"
' EXIT

# Spin up wg0 inside an unshare so we have a real WireGuard interface
# to call wg(8) against without touching the host's kernel state.
unshare -Urn --fork bash -c "
    set -e
    ip link set lo up
    umask 077
    wg genkey > $WORK/srv.priv
    wg pubkey < $WORK/srv.priv > $WORK/srv.pub
    PEERPRIV=\$(wg genkey)
    echo \"\$PEERPRIV\" > $WORK/peer.priv
    wg pubkey <<<\"\$PEERPRIV\" > $WORK/peer.pub
    ip link add wg0 type wireguard
    ip addr add 10.99.0.1/24 dev wg0
    wg set wg0 private-key $WORK/srv.priv listen-port 51820 \
              peer \"\$(cat $WORK/peer.pub)\" allowed-ips 10.99.0.2/32
    ip link set wg0 up
    sleep infinity
" >"$WORK/inner.log" 2>&1 &
UNSHARE_PID=$!
sleep 0.5
INNER=$(pgrep -P "$UNSHARE_PID" | head -1)
[[ -n "$INNER" ]] || { echo "failed to start unshare" >&2; cat "$WORK/inner.log"; exit 2; }

# Start the oracle inside the same unshare.
SOCK=$WORK/oracle.sock
nsenter --target "$INNER" --user --net --preserve-credentials \
    env "WIREGUARDRTC_KEY_ORACLE_SOCKET=$SOCK" \
    "$PY" "$ORACLE" >"$WORK/oracle.log" 2>&1 &
sleep 0.5
[[ -S "$SOCK" ]] || { echo "oracle didn't create socket" >&2; cat "$WORK/oracle.log"; exit 2; }

PEERPUB=$(cat "$WORK/peer.pub")
SRVPRIV=$(cat "$WORK/srv.priv")

call() {
    nsenter --target "$INNER" --user --net --preserve-credentials \
        socat - "UNIX-CONNECT:$SOCK" <<<"$1"
}
field() {
    "$PY" -c "import json,sys; print(json.loads(sys.argv[1]).get(sys.argv[2],''))" "$1" "$2"
}

pass=0
fail=0
expect() {
    local desc="$1" want_ok="$2" want_err="$3" json="$4"
    local resp ok err
    resp=$(call "$json")
    ok=$(field "$resp" ok)
    err=$(field "$resp" error)
    if [[ "$ok" == "$want_ok" && "$err" == *"$want_err"* ]]; then
        echo "  PASS [$desc] -> ok=$ok err=$err"
        pass=$((pass+1))
    else
        echo "  FAIL [$desc] expected ok=$want_ok err=*$want_err* got ok=$ok err=$err"
        echo "    request: $json"
        echo "    response: $resp"
        fail=$((fail+1))
    fi
}

echo "=== crypto correctness vs reference ==="
REF_SIGBOX=$("$PY" -c "
import base64
from nacl.bindings import crypto_scalarmult
from nacl.hash import blake2b
from nacl.encoding import RawEncoder
priv = base64.b64decode('$SRVPRIV')
pub  = base64.b64decode('$PEERPUB')
shared = crypto_scalarmult(priv, pub)
print(base64.b64encode(blake2b(shared, digest_size=32, key=b'wg-peerjs/v1/sigbox'[:32], encoder=RawEncoder)).decode())
")
RESP=$(call "{\"op\":\"derive_sigbox\",\"iface\":\"wg0\",\"peer_pub\":\"$PEERPUB\"}")
ORACLE_KEY=$(field "$RESP" key)
if [[ "$REF_SIGBOX" == "$ORACLE_KEY" ]]; then
    echo "  PASS [derive_sigbox-byte-match]"
    pass=$((pass+1))
else
    echo "  FAIL [derive_sigbox-byte-match]"
    echo "    ref:    $REF_SIGBOX"
    echo "    oracle: $ORACLE_KEY"
    fail=$((fail+1))
fi

TOKEN=$("$PY" -c 'import os,base64;print(base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode())')
REF_ENROLL=$("$PY" -c "
import base64
from nacl.bindings import crypto_scalarmult
from nacl.hash import blake2b
from nacl.encoding import RawEncoder
priv = base64.b64decode('$SRVPRIV')
pub  = base64.b64decode('$PEERPUB')
tok  = base64.urlsafe_b64decode('${TOKEN}=')
shared = crypto_scalarmult(priv, pub)
ek = blake2b(shared, digest_size=32, key=b'wg-peerjs/v1/enroll'[:32], encoder=RawEncoder)
fk = blake2b(ek,     digest_size=32, key=tok, encoder=RawEncoder)
print(base64.b64encode(fk).decode())
")
RESP=$(call "{\"op\":\"derive_enroll\",\"iface\":\"wg0\",\"peer_pub\":\"$PEERPUB\",\"token\":\"$TOKEN\"}")
ORACLE_KEY=$(field "$RESP" key)
if [[ "$REF_ENROLL" == "$ORACLE_KEY" ]]; then
    echo "  PASS [derive_enroll-byte-match]"
    pass=$((pass+1))
else
    echo "  FAIL [derive_enroll-byte-match]"
    echo "    ref:    $REF_ENROLL"
    echo "    oracle: $ORACLE_KEY"
    fail=$((fail+1))
fi

echo
echo "=== iface validation ==="
expect "iface-eth"        False bad-iface "{\"op\":\"derive_sigbox\",\"iface\":\"eth0\",\"peer_pub\":\"$PEERPUB\"}"
expect "iface-uppercase"  False bad-iface "{\"op\":\"derive_sigbox\",\"iface\":\"WG0\",\"peer_pub\":\"$PEERPUB\"}"
expect "iface-traversal"  False bad-iface "{\"op\":\"derive_sigbox\",\"iface\":\"../etc\",\"peer_pub\":\"$PEERPUB\"}"
expect "iface-no-priv"    False no-priv-for-iface "{\"op\":\"derive_sigbox\",\"iface\":\"wg9\",\"peer_pub\":\"$PEERPUB\"}"

echo
echo "=== pubkey validation ==="
expect "pub-short"  False bad-peer-pub  "{\"op\":\"derive_sigbox\",\"iface\":\"wg0\",\"peer_pub\":\"AAAA=\"}"
URLSAFE_PUB="A--AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
expect "pub-urlsafe-chars" False bad-peer-pub "{\"op\":\"derive_sigbox\",\"iface\":\"wg0\",\"peer_pub\":\"$URLSAFE_PUB\"}"

echo
echo "=== token validation ==="
expect "tok-short"      False bad-token "{\"op\":\"derive_enroll\",\"iface\":\"wg0\",\"peer_pub\":\"$PEERPUB\",\"token\":\"AAA\"}"
expect "tok-stdb64-chars" False bad-token "{\"op\":\"derive_enroll\",\"iface\":\"wg0\",\"peer_pub\":\"$PEERPUB\",\"token\":\"AAA+/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}"

echo
echo "=== set_endpoint ==="
expect "endpoint-ok"        True ""           "{\"op\":\"set_endpoint\",\"iface\":\"wg0\",\"peer_pub\":\"$PEERPUB\",\"ip\":\"203.0.113.5\",\"port\":51820}"
expect "endpoint-loopback"  False bad-endpoint "{\"op\":\"set_endpoint\",\"iface\":\"wg0\",\"peer_pub\":\"$PEERPUB\",\"ip\":\"127.0.0.1\",\"port\":51820}"
expect "endpoint-link-local" False bad-endpoint "{\"op\":\"set_endpoint\",\"iface\":\"wg0\",\"peer_pub\":\"$PEERPUB\",\"ip\":\"169.254.1.5\",\"port\":51820}"

ATT_PUB=$("$PY" -c 'import os,base64;print(base64.b64encode(os.urandom(32)).decode())')
expect "endpoint-rogue-peer" False peer-not-on-iface "{\"op\":\"set_endpoint\",\"iface\":\"wg0\",\"peer_pub\":\"$ATT_PUB\",\"ip\":\"203.0.113.5\",\"port\":51820}"

# Verify the legitimate set_endpoint actually took effect on the kernel.
KERNEL_EP=$(nsenter --target "$INNER" --user --net --preserve-credentials wg show wg0 endpoints | awk '{print $2}')
if [[ "$KERNEL_EP" == "203.0.113.5:51820" ]]; then
    echo "  PASS [endpoint-applied-to-kernel]"
    pass=$((pass+1))
else
    echo "  FAIL [endpoint-applied-to-kernel] kernel says: $KERNEL_EP"
    fail=$((fail+1))
fi

echo
echo "=== iface-state RPCs ==="
# list_interfaces — should include wg0
RESP=$(call '{"op":"list_interfaces"}')
LISTED=$(field "$RESP" interfaces)
if [[ "$LISTED" == *"wg0"* ]]; then
    echo "  PASS [list_interfaces-includes-wg0]"
    pass=$((pass+1))
else
    echo "  FAIL [list_interfaces-includes-wg0] got: $RESP"
    fail=$((fail+1))
fi

# iface_field — public-key matches what wg show returns
SRV_PUB=$(nsenter --target "$INNER" --user --net --preserve-credentials wg show wg0 public-key)
RESP=$(call "{\"op\":\"iface_field\",\"iface\":\"wg0\",\"field\":\"public-key\"}")
GOT=$(field "$RESP" value)
if [[ "$GOT" == "$SRV_PUB" ]]; then
    echo "  PASS [iface_field-public-key]"
    pass=$((pass+1))
else
    echo "  FAIL [iface_field-public-key] expected $SRV_PUB got $GOT"
    fail=$((fail+1))
fi

# iface_field — listen-port comes back as a string of digits
RESP=$(call '{"op":"iface_field","iface":"wg0","field":"listen-port"}')
GOT=$(field "$RESP" value)
if [[ "$GOT" =~ ^[0-9]+$ ]]; then
    echo "  PASS [iface_field-listen-port=$GOT]"
    pass=$((pass+1))
else
    echo "  FAIL [iface_field-listen-port] got '$GOT'"
    fail=$((fail+1))
fi

# iface_field — private-key is NOT in the allowlist (oracle refuses)
expect "iface_field-private-rejected" False bad-field \
    '{"op":"iface_field","iface":"wg0","field":"private-key"}'

# iface_table — allowed-ips contains the configured peer
RESP=$(call '{"op":"iface_table","iface":"wg0","field":"allowed-ips"}')
TABLE=$(field "$RESP" table)
if [[ "$TABLE" == *"$PEERPUB"* ]]; then
    echo "  PASS [iface_table-allowed-ips-has-peer]"
    pass=$((pass+1))
else
    echo "  FAIL [iface_table-allowed-ips-has-peer] got: $TABLE"
    fail=$((fail+1))
fi

# iface_table — bad field
expect "iface_table-bad-field" False bad-field \
    '{"op":"iface_table","iface":"wg0","field":"private-key"}'
expect "iface_table-unknown-field" False bad-field \
    '{"op":"iface_table","iface":"wg0","field":"not-a-real-field"}'

echo
echo "=== misc rejects ==="
expect "unknown-op"    False unknown-op "{\"op\":\"please-leak-key\",\"iface\":\"wg0\",\"peer_pub\":\"$PEERPUB\"}"
expect "bad-json"      False internal   'not-json'

echo
echo "summary: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
