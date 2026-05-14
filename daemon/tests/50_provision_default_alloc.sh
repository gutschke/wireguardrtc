#!/bin/bash
# 50_provision_default_alloc.sh — exercise the address-allocation logic
# in wireguardrtc-provision-default.
#
# F4 scope: the script must reserve [Interface] Address and any
#   existing [Peer] AllowedIPs in the pool when picking a slot for the
#   new peer.
# F5 scope: when WIREGUARDRTC_PROVISION_ASSIGNED_ADDRESS is set, the
#   script must use it directly and skip the allocator.
#
# Tests run against a temporary wg0.conf — we don't actually need a
# live WG interface, so the `wg syncconf` step is stubbed by putting a
# noop `wg` shim earlier on PATH.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$REPO/wireguardrtc-provision-default"

[[ -x "$SCRIPT" ]] || { echo "missing $SCRIPT"; exit 1; }

# Shim `wg` and `wg-quick` so the post-allocation `wg syncconf` doesn't
# need a real kernel interface.  Provision-default reads `wg show
# IFACE allowed-ips` to find live allocations, and `wg-quick strip
# IFACE` to produce a normalised config it passes to `wg syncconf`.
SHIMDIR=$(mktemp -d)
trap 'rm -rf "$SHIMDIR" "$TMPCONF" "$TMPPROV" "$TMPWG"' EXIT
cat > "$SHIMDIR/wg" <<'WG'
#!/bin/bash
case "$1" in
    show)         exit 0 ;;
    syncconf)     # consume stdin from the process-substitution
                  cat > /dev/null
                  exit 0 ;;
    *)            exit 0 ;;
esac
WG
cat > "$SHIMDIR/wg-quick" <<'WGQ'
#!/bin/bash
# Only invoked as "wg-quick strip IFACE".  Echo the iface conf so
# `wg syncconf` (also shimmed) gets a valid input.
case "$1" in
    strip) cat "/tmp/wg-${2}.conf" 2>/dev/null || true ; exit 0 ;;
    *) exit 0 ;;
esac
WGQ
chmod +x "$SHIMDIR/wg" "$SHIMDIR/wg-quick"
export PATH="$SHIMDIR:$PATH"

# Per-test files; recreated each test.
TMPCONF=""
TMPPROV=""
TMPWG=""

fresh_files() {
    TMPCONF=$(mktemp /tmp/wgrtc-conf-XXXX.conf)
    TMPPROV=$(mktemp /tmp/wgrtc-prov-XXXX.conf)
    TMPWG=/tmp/wg-testwg.conf
    # provision-default hardcodes paths — we override via env vars
    # that the script must learn to honour.  For now monkey-patch by
    # writing to the expected locations and pointing CONF/WG_CONF
    # explicitly.
    cp "$TMPCONF" "/tmp/wg-testwg.conf"
}

run_provision() {
    # Args: NAME PUBKEY ASSIGNED_ADDR (optional, empty for allocator)
    local name="$1" pubkey="$2" assigned="${3:-}"
    local extra_env=""
    if [[ -n "$assigned" ]]; then
        extra_env="WIREGUARDRTC_PROVISION_ASSIGNED_ADDRESS=$assigned"
    fi
    env -i PATH="$PATH" HOME="$HOME" \
        WIREGUARDRTC_PROVISIONING_CONF="$TMPPROV" \
        WIREGUARDRTC_WG_CONF="$TMPWG" \
        ${extra_env} \
        "$SCRIPT" testwg "$name" "$pubkey" 2>&1
}

allocated_addr() {
    # Extract the last AllowedIPs line, strip /32 suffix.
    tail -n5 "$TMPWG" | awk '/^AllowedIPs/{print $3}' | sed 's,/.*,,'
}


# ─── F4 tests ──────────────────────────────────────────────────────

test_f4_first_alloc_skips_interface_address() {
    fresh_files
    cat > "$TMPWG" <<EOF
[Interface]
PrivateKey = $(head -c32 /dev/urandom | base64)
Address = 10.0.0.1/24
ListenPort = 51820
EOF
    cat > "$TMPPROV" <<EOF
Pool = 10.0.0.0/24
EOF
    run_provision alice $(head -c32 /dev/urandom | base64) >/dev/null
    got=$(allocated_addr)
    if [[ "$got" == "10.0.0.1" ]]; then
        echo "  ✗ test_f4_first_alloc_skips_interface_address: allocated server's own address 10.0.0.1"
        return 1
    fi
    if [[ "$got" != "10.0.0.2" ]]; then
        echo "  ✗ test_f4_first_alloc_skips_interface_address: expected 10.0.0.2, got $got"
        return 1
    fi
    echo "  ✓ test_f4_first_alloc_skips_interface_address"
}

test_f4_alloc_skips_existing_peers() {
    fresh_files
    cat > "$TMPWG" <<EOF
[Interface]
Address = 10.0.0.1/24

[Peer]
PublicKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
AllowedIPs = 10.0.0.2/32

[Peer]
PublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=
AllowedIPs = 10.0.0.3/32
EOF
    cat > "$TMPPROV" <<EOF
Pool = 10.0.0.0/24
EOF
    run_provision charlie $(head -c32 /dev/urandom | base64) >/dev/null
    got=$(allocated_addr)
    if [[ "$got" != "10.0.0.4" ]]; then
        echo "  ✗ test_f4_alloc_skips_existing_peers: expected 10.0.0.4, got $got"
        return 1
    fi
    echo "  ✓ test_f4_alloc_skips_existing_peers"
}

test_f4_alloc_fills_gaps() {
    fresh_files
    cat > "$TMPWG" <<EOF
[Interface]
Address = 10.0.0.1/24

[Peer]
PublicKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
AllowedIPs = 10.0.0.5/32
EOF
    cat > "$TMPPROV" <<EOF
Pool = 10.0.0.0/24
EOF
    run_provision dave $(head -c32 /dev/urandom | base64) >/dev/null
    got=$(allocated_addr)
    # Allocator should pick the lowest free address — 10.0.0.2.
    if [[ "$got" != "10.0.0.2" ]]; then
        echo "  ✗ test_f4_alloc_fills_gaps: expected 10.0.0.2, got $got"
        return 1
    fi
    echo "  ✓ test_f4_alloc_fills_gaps"
}


# ─── F5 tests ──────────────────────────────────────────────────────

test_f5_honors_assigned_address_env() {
    fresh_files
    cat > "$TMPWG" <<EOF
[Interface]
Address = 10.0.0.1/24
EOF
    cat > "$TMPPROV" <<EOF
Pool = 10.0.0.0/24
EOF
    run_provision eve $(head -c32 /dev/urandom | base64) 10.0.0.42 >/dev/null
    got=$(allocated_addr)
    if [[ "$got" != "10.0.0.42" ]]; then
        echo "  ✗ test_f5_honors_assigned_address_env: expected 10.0.0.42, got $got"
        return 1
    fi
    echo "  ✓ test_f5_honors_assigned_address_env"
}

test_f5_assigned_outside_pool_is_rejected() {
    fresh_files
    cat > "$TMPWG" <<EOF
[Interface]
Address = 10.0.0.1/24
EOF
    cat > "$TMPPROV" <<EOF
Pool = 10.0.0.0/24
EOF
    if run_provision frank $(head -c32 /dev/urandom | base64) 192.168.99.1 >/dev/null; then
        echo "  ✗ test_f5_assigned_outside_pool_is_rejected: script accepted 192.168.99.1 outside 10.0.0.0/24"
        return 1
    fi
    echo "  ✓ test_f5_assigned_outside_pool_is_rejected"
}

test_f5_assigned_collides_with_existing_is_rejected() {
    fresh_files
    cat > "$TMPWG" <<EOF
[Interface]
Address = 10.0.0.1/24

[Peer]
PublicKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
AllowedIPs = 10.0.0.10/32
EOF
    cat > "$TMPPROV" <<EOF
Pool = 10.0.0.0/24
EOF
    if run_provision grace $(head -c32 /dev/urandom | base64) 10.0.0.10 >/dev/null; then
        echo "  ✗ test_f5_assigned_collides_with_existing_is_rejected: script accepted address already in use"
        return 1
    fi
    echo "  ✓ test_f5_assigned_collides_with_existing_is_rejected"
}


# ─── Driver ────────────────────────────────────────────────────────

failures=0
for t in \
    test_f4_first_alloc_skips_interface_address \
    test_f4_alloc_skips_existing_peers \
    test_f4_alloc_fills_gaps \
    test_f5_honors_assigned_address_env \
    test_f5_assigned_outside_pool_is_rejected \
    test_f5_assigned_collides_with_existing_is_rejected
do
    if ! $t; then
        failures=$((failures + 1))
    fi
done
echo
total=6
echo "$((total - failures))/$total passed"
exit $failures
