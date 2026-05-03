#!/bin/bash
# 17_raw_helper.sh — unit-ish test of the privileged raw-socket helper.
#
# Exercises wireguardrtc-raw-helper's two RPCs (inject, wake) and its
# validation/rejection paths against a real WireGuard interface inside
# an unprivileged user namespace.  The helper sends spoofed-source-port
# UDP packets and SO_BINDTODEVICE-bound wake datagrams, both of which
# are observable but hard to verify byte-exactly without packet
# capture privileges; instead we verify the RETURN status of each RPC
# (ok vs the specific reject reason) and that the inject's destination
# ip/port + iface reach the helper unchanged.
#
# Coverage:
#   * inject: legitimate src_port (matches iface listen-port) succeeds
#   * inject: src_port mismatch → src-port-mismatch
#   * inject: dst_ip loopback / link-local / multicast / reserved → bad-dst-endpoint
#   * inject: bad iface (eth0, traversal, missing) → bad-iface / iface-not-present
#   * wake:   legitimate succeeds
#   * wake:   bad iface → bad-iface / iface-not-present
#   * wake:   junk target_ip → bad-target-ip
#   * unknown op → unknown-op
#   * malformed JSON → internal:JSONDecodeError

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
HELPER="$REPO/wireguardrtc-raw-helper"
PY="${PY:-$REPO/venv/bin/python3}"

[[ -x "$HELPER" ]] || { echo "error: $HELPER not found" >&2; exit 2; }
[[ -x "$PY" ]]     || { echo "error: $PY not found" >&2; exit 2; }
command -v unshare >/dev/null || { echo "need unshare" >&2; exit 2; }
command -v socat   >/dev/null || { echo "need socat" >&2; exit 2; }
command -v wg      >/dev/null || { echo "need wg(8)" >&2; exit 2; }

WORK=$(mktemp -d)
trap '
    pkill -P $$ 2>/dev/null ||:
    rm -rf "$WORK"
' EXIT

# Spin up wg0 inside an unshare so we have a real WireGuard listen-port
# that the helper can verify against.  Listen-port 51820, peer with /32.
unshare -Urn --fork bash -c "
    set -e
    ip link set lo up
    umask 077
    wg genkey > $WORK/srv.priv
    PEER=\$(wg genkey | wg pubkey)
    ip link add wg0 type wireguard
    ip addr add 10.99.0.1/24 dev wg0
    wg set wg0 private-key $WORK/srv.priv listen-port 51820 \
              peer \"\$PEER\" allowed-ips 10.99.0.2/32
    ip link set wg0 up
    sleep infinity
" >"$WORK/inner.log" 2>&1 &
UNSHARE_PID=$!
sleep 0.5
INNER=$(pgrep -P "$UNSHARE_PID" | head -1)
[[ -n "$INNER" ]] || { echo "failed to start unshare" >&2; cat "$WORK/inner.log"; exit 2; }

SOCK=$WORK/raw.sock
nsenter --target "$INNER" --user --net --preserve-credentials \
    env "WIREGUARDRTC_RAW_HELPER_SOCKET=$SOCK" \
    "$PY" "$HELPER" >"$WORK/helper.log" 2>&1 &
sleep 0.5
[[ -S "$SOCK" ]] || { echo "helper didn't create socket" >&2; cat "$WORK/helper.log"; exit 2; }

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

echo "=== inject ==="
expect "inject-ok"        True ""             '{"op":"inject","iface":"wg0","src_port":51820,"dst_ip":"203.0.113.5","dst_port":51820}'
expect "inject-mismatch"  False src-port-mismatch '{"op":"inject","iface":"wg0","src_port":1234,"dst_ip":"203.0.113.5","dst_port":51820}'
expect "inject-loopback"  False bad-dst-endpoint  '{"op":"inject","iface":"wg0","src_port":51820,"dst_ip":"127.0.0.1","dst_port":51820}'
expect "inject-linklocal" False bad-dst-endpoint  '{"op":"inject","iface":"wg0","src_port":51820,"dst_ip":"169.254.1.5","dst_port":51820}'
expect "inject-mcast"     False bad-dst-endpoint  '{"op":"inject","iface":"wg0","src_port":51820,"dst_ip":"239.0.0.1","dst_port":51820}'
expect "inject-unspec"    False bad-dst-endpoint  '{"op":"inject","iface":"wg0","src_port":51820,"dst_ip":"0.0.0.0","dst_port":51820}'
expect "inject-broadcast" False bad-dst-endpoint  '{"op":"inject","iface":"wg0","src_port":51820,"dst_ip":"255.255.255.255","dst_port":51820}'
expect "inject-bad-iface" False bad-iface         '{"op":"inject","iface":"eth0","src_port":51820,"dst_ip":"203.0.113.5","dst_port":51820}'
expect "inject-traversal" False bad-iface         '{"op":"inject","iface":"../etc","src_port":51820,"dst_ip":"203.0.113.5","dst_port":51820}'
expect "inject-no-iface"  False iface-not-present '{"op":"inject","iface":"wg9","src_port":51820,"dst_ip":"203.0.113.5","dst_port":51820}'
expect "inject-bad-port"  False bad-src-port      '{"op":"inject","iface":"wg0","src_port":0,"dst_ip":"203.0.113.5","dst_port":51820}'

echo
echo "=== wake ==="
expect "wake-ok"          True ""             '{"op":"wake","iface":"wg0","target_ip":"10.99.0.2"}'
expect "wake-catchall"    True ""             '{"op":"wake","iface":"wg0","target_ip":"192.0.2.1"}'
expect "wake-bad-iface"   False bad-iface         '{"op":"wake","iface":"eth0","target_ip":"10.99.0.2"}'
expect "wake-no-iface"    False iface-not-present '{"op":"wake","iface":"wg9","target_ip":"10.99.0.2"}'
expect "wake-junk-ip"     False bad-target-ip     '{"op":"wake","iface":"wg0","target_ip":"not-an-ip"}'
expect "wake-v6"          False bad-target-ip     '{"op":"wake","iface":"wg0","target_ip":"::1"}'

echo
echo "=== misc ==="
expect "unknown-op"       False unknown-op        '{"op":"please-leak","iface":"wg0"}'
expect "bad-json"         False internal          'not-json'

echo
echo "summary: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
