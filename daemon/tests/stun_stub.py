#!/usr/bin/env python3
"""Minimal RFC 5389 STUN BINDING responder for tests.

Listens on a UDP port, replies to BINDING REQUEST messages with a
BINDING RESPONSE containing the XOR-MAPPED-ADDRESS attribute set to the
sender's source IP and port.  About 50 lines of code; sufficient for
the wireguardrtc daemon's get_public_ipv4() to work inside test
fabrics that don't have real internet egress.

Usage:
    stun_stub.py [--bind 0.0.0.0] [--port 3478]
"""

import argparse
import socket
import struct
import sys

STUN_MAGIC_COOKIE = 0x2112A442
BINDING_REQUEST = 0x0001
BINDING_RESPONSE = 0x0101
XOR_MAPPED_ADDRESS = 0x0020


def build_response(txid: bytes, src_ip: str, src_port: int) -> bytes:
    # XOR-MAPPED-ADDRESS payload (IPv4, 8 bytes total)
    family = 0x01
    xport = src_port ^ (STUN_MAGIC_COOKIE >> 16)
    xip = struct.unpack("!L", socket.inet_aton(src_ip))[0] ^ STUN_MAGIC_COOKIE
    attr_value = struct.pack("!BBH4s",
                             0,           # reserved
                             family,
                             xport,
                             struct.pack("!L", xip))
    attr = struct.pack("!HH", XOR_MAPPED_ADDRESS, len(attr_value)) + attr_value
    msg_len = len(attr)
    header = struct.pack("!HHL12s", BINDING_RESPONSE, msg_len,
                         STUN_MAGIC_COOKIE, txid)
    return header + attr


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=3478)
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    print(f"stun_stub listening on {args.bind}:{args.port}", flush=True)

    while True:
        try:
            data, addr = sock.recvfrom(2048)
        except KeyboardInterrupt:
            return
        if len(data) < 20:
            continue
        msg_type, msg_len, magic, txid = struct.unpack("!HHL12s", data[:20])
        if msg_type != BINDING_REQUEST or magic != STUN_MAGIC_COOKIE:
            continue
        resp = build_response(txid, addr[0], addr[1])
        sock.sendto(resp, addr)


if __name__ == "__main__":
    sys.exit(main())
