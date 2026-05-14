#!/usr/bin/env python3
# 32_stun_parse.py — unit tests for the daemon's STUN XOR-MAPPED-ADDRESS
# parser.  Synthetic packets, no sockets.
#
# The parser is the bottleneck for IPv6 NAT discovery: family=0x02 in
# the XOR-MAPPED-ADDRESS attribute means the address is XORed with the
# magic cookie concatenated with the transaction id (RFC 5389 §15.2).
# A v4-only parser silently drops v6 replies and gives the appearance
# that v6 is unreachable.  Cover both families explicitly.

import importlib.machinery
import importlib.util
import os
import socket
import struct
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
loader = importlib.machinery.SourceFileLoader(
    "wgrtc", os.path.join(REPO, "wireguardrtc"))
spec = importlib.util.spec_from_loader("wgrtc", loader)
wgrtc = importlib.util.module_from_spec(spec)
loader.exec_module(wgrtc)


MAGIC = 0x2112A442


def _build_response(txid, attrs):
    """attrs: bytes containing concatenated TLV attributes."""
    header = struct.pack("!HHL12s", 0x0101, len(attrs), MAGIC, txid)
    return header + attrs


def _xor_mapped_v4(ext_ip, ext_port):
    xport = ext_port ^ (MAGIC >> 16)
    ip_int = struct.unpack("!L", socket.inet_aton(ext_ip))[0]
    xip = ip_int ^ MAGIC
    payload = struct.pack("!BBHL", 0, 0x01, xport, xip)
    return struct.pack("!HH", 0x0020, len(payload)) + payload


def _xor_mapped_v6(ext_ip, ext_port, txid):
    xport = ext_port ^ (MAGIC >> 16)
    raw = socket.inet_pton(socket.AF_INET6, ext_ip)
    mask = struct.pack("!L", MAGIC) + txid
    xip = bytes(a ^ b for a, b in zip(raw, mask))
    payload = struct.pack("!BB", 0, 0x02) + struct.pack("!H", xport) + xip
    return struct.pack("!HH", 0x0020, len(payload)) + payload


# ─── v4 ─────────────────────────────────────────────────────────────────

def test_parse_v4_response():
    txid = b"\x42" * 12
    attrs = _xor_mapped_v4("203.0.113.42", 54321)
    pkt = _build_response(txid, attrs)
    out = wgrtc._parse_stun_xor_mapped(pkt, txid)
    assert out == ("203.0.113.42", 54321), out


def test_parse_v4_with_padded_unknown_attribute_before():
    txid = b"\x55" * 12
    # SOFTWARE-like attribute with a 3-byte payload (1 byte pad).
    unknown = struct.pack("!HH3s", 0x8022, 3, b"abc") + b"\x00"
    attrs = unknown + _xor_mapped_v4("198.51.100.1", 33445)
    pkt = _build_response(txid, attrs)
    out = wgrtc._parse_stun_xor_mapped(pkt, txid)
    assert out == ("198.51.100.1", 33445), out


# ─── v6 ─────────────────────────────────────────────────────────────────

def test_parse_v6_response_global():
    txid = bytes(range(12))
    attrs = _xor_mapped_v6("2001:db8::1234", 51820, txid)
    pkt = _build_response(txid, attrs)
    out = wgrtc._parse_stun_xor_mapped(pkt, txid)
    assert out is not None
    ip, port = out
    assert socket.inet_pton(socket.AF_INET6, ip) == \
        socket.inet_pton(socket.AF_INET6, "2001:db8::1234"), ip
    assert port == 51820, port


def test_parse_v6_response_ula():
    # Unique-local addresses use a different prefix; covers the case
    # where the parser must NOT special-case "looks like 2001:db8".
    txid = b"\xaa" * 12
    attrs = _xor_mapped_v6("fd12:3456:789a::1", 1234, txid)
    pkt = _build_response(txid, attrs)
    out = wgrtc._parse_stun_xor_mapped(pkt, txid)
    assert out is not None
    ip, port = out
    assert socket.inet_pton(socket.AF_INET6, ip) == \
        socket.inet_pton(socket.AF_INET6, "fd12:3456:789a::1"), ip
    assert port == 1234


# ─── reject malformed / wrong-txid ─────────────────────────────────────

def test_reject_wrong_txid():
    txid = b"\x42" * 12
    attrs = _xor_mapped_v4("203.0.113.42", 1234)
    pkt = _build_response(txid, attrs)
    out = wgrtc._parse_stun_xor_mapped(pkt, b"\x99" * 12)
    assert out is None, out


def test_reject_non_response_type():
    txid = b"\x42" * 12
    attrs = _xor_mapped_v4("203.0.113.42", 1234)
    # Build with a binding REQUEST type (0x0001) instead of RESPONSE.
    bad = struct.pack("!HHL12s", 0x0001, len(attrs), MAGIC, txid) + attrs
    out = wgrtc._parse_stun_xor_mapped(bad, txid)
    assert out is None, out


def test_reject_too_short():
    out = wgrtc._parse_stun_xor_mapped(b"\x00" * 10, b"\x42" * 12)
    assert out is None, out


def test_no_xor_mapped_attribute():
    # Response with only a SOFTWARE-like attribute, no XOR-MAPPED-ADDRESS.
    txid = b"\x42" * 12
    attrs = struct.pack("!HH4s", 0x8022, 4, b"test")
    pkt = _build_response(txid, attrs)
    out = wgrtc._parse_stun_xor_mapped(pkt, txid)
    assert out is None, out


# ─── Driver ─────────────────────────────────────────────────────────────

def main():
    tests = [
        test_parse_v4_response,
        test_parse_v4_with_padded_unknown_attribute_before,
        test_parse_v6_response_global,
        test_parse_v6_response_ula,
        test_reject_wrong_txid,
        test_reject_non_response_type,
        test_reject_too_short,
        test_no_xor_mapped_attribute,
    ]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"  ✓ {t.__name__}")
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}")
            failures += 1
    print()
    print(f"{len(tests) - failures}/{len(tests)} passed")
    sys.exit(0 if failures == 0 else 1)


if __name__ == "__main__":
    main()
