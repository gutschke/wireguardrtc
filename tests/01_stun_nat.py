#!/usr/bin/env python3
"""
NAT type & port-preservation classifier.

Sends STUN binding requests from several source ports to several STUN servers
and observes how the upstream NAT (if any) maps them. Determines:

    - whether the same source port maps to the same external port across
      different destination IPs (cone vs. symmetric NAT)
    - whether the external port equals the source port (port-preserving NAT)

The daemon's STUN-then-publish-(public_ip, listen_port) approach only works
on cone-style port-preserving NATs. This test tells you whether you have one.

Usage: ./01_stun_nat.py [--quick]

Sends 6 small UDP packets total to 3 well-known STUN servers, with a 2 s
per-request timeout. Safe to run on a live machine; does not modify anything.
"""

import argparse
import os
import socket
import struct
import sys
import time

MAGIC_COOKIE = 0x2112A442
DEFAULT_STUN_SERVERS = [
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "stun.nextcloud.com:3478",
]


def stun_binding_request(sock, server_host, server_port, timeout=2.0):
    """Send a STUN binding request and parse XOR-MAPPED-ADDRESS from the reply.

    Returns (external_ip, external_port) or raises on failure.
    """
    # Resolve the server fresh each time — avoids any cached A-record issue.
    ip = socket.gethostbyname(server_host)

    txid = os.urandom(12)
    # Type=0x0001 (binding request), length=0, magic cookie, txid
    request = struct.pack("!HHL12s", 0x0001, 0, MAGIC_COOKIE, txid)

    sock.settimeout(timeout)
    sock.sendto(request, (ip, server_port))

    deadline = time.time() + timeout
    while time.time() < deadline:
        data, _ = sock.recvfrom(2048)
        if len(data) < 20:
            continue
        msg_type, msg_len, magic, resp_txid = struct.unpack("!HHL12s", data[:20])
        # Only accept binding-success responses with our txid.
        if msg_type != 0x0101 or magic != MAGIC_COOKIE or resp_txid != txid:
            continue

        offset = 20
        end = 20 + msg_len
        while offset + 4 <= end:
            attr_type, attr_len = struct.unpack("!HH", data[offset:offset + 4])
            offset += 4
            if attr_type == 0x0020 and attr_len >= 8:  # XOR-MAPPED-ADDRESS
                family = data[offset + 1]
                if family != 0x01:  # IPv4 only here
                    offset += attr_len + ((4 - (attr_len % 4)) % 4)
                    continue
                xport = struct.unpack("!H", data[offset + 2:offset + 4])[0]
                xip = struct.unpack("!L", data[offset + 4:offset + 8])[0]
                ext_port = xport ^ (MAGIC_COOKIE >> 16)
                ext_ip = socket.inet_ntoa(struct.pack("!L", xip ^ MAGIC_COOKIE))
                return ext_ip, ext_port
            offset += attr_len + ((4 - (attr_len % 4)) % 4)
        raise RuntimeError("XOR-MAPPED-ADDRESS not found in response")

    raise TimeoutError("no STUN response received")


def probe(server, src_port):
    """Bind a fresh socket to src_port and send one STUN request."""
    host, port = server.rsplit(":", 1)
    port = int(port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", src_port))
    except OSError as e:
        raise RuntimeError(f"could not bind src_port {src_port}: {e}")
    try:
        ext_ip, ext_port = stun_binding_request(sock, host, port)
        local_port = sock.getsockname()[1]
        return local_port, ext_ip, ext_port
    finally:
        sock.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true",
                    help="use only 2 STUN servers (4 packets total)")
    ap.add_argument("--servers", nargs="+", default=None,
                    help="STUN servers as host:port (overrides default list)")
    args = ap.parse_args()

    servers = args.servers or DEFAULT_STUN_SERVERS
    if args.quick:
        servers = servers[:2]

    # Pick three distinct ephemeral source ports. Asking the kernel for 0 lets
    # it choose, then we read it back. This avoids picking already-used ports.
    src_ports = []
    for _ in range(3):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", 0))
        src_ports.append(s.getsockname()[1])
        s.close()
        time.sleep(0.05)  # let the kernel reuse-window expire

    print(f"Source ports chosen: {src_ports}")
    print(f"STUN servers: {servers}")
    print()

    # results[(server, src_port)] = (local_port_actually_used, ext_ip, ext_port)
    results = {}
    failures = []
    for server in servers:
        for src_port in src_ports:
            try:
                local, ext_ip, ext_port = probe(server, src_port)
                results[(server, local)] = (ext_ip, ext_port)
                preservation = "preserved" if ext_port == local else "remapped"
                print(f"  {server:32s}  src={local:>5d}  ->  {ext_ip}:{ext_port}  ({preservation})")
            except Exception as e:
                failures.append((server, src_port, str(e)))
                print(f"  {server:32s}  src={src_port:>5d}  ->  FAILED: {e}")

    if not results:
        print("\nNo successful STUN responses — cannot classify NAT.")
        print("Possible causes: outbound UDP blocked, all STUN servers unreachable.")
        sys.exit(2)

    # External IP — should be a single value. If multiple, something is weird
    # (multi-WAN? STUN server returning different perspectives?).
    ext_ips = {ip for ip, _ in results.values()}
    print()
    print(f"Distinct external IPs observed: {sorted(ext_ips)}")

    # Port preservation: for each src_port, are external ports equal to it
    # across all servers?
    preserving = True
    for src_port in src_ports:
        ext_ports_for_src = {
            ext_port for (server, lp), (_, ext_port) in results.items()
            if lp == src_port
        }
        if not ext_ports_for_src:
            continue
        if len(ext_ports_for_src) > 1 or src_port not in ext_ports_for_src:
            preserving = False
            break
    # Cone vs symmetric: for each src_port, are all external ports the same
    # across destinations? If yes for all → cone. If no for any → symmetric.
    cone = True
    for src_port in src_ports:
        ext_ports_for_src = {
            ext_port for (server, lp), (_, ext_port) in results.items()
            if lp == src_port
        }
        if len(ext_ports_for_src) > 1:
            cone = False
            break

    print()
    print("Verdict:")
    if cone and preserving:
        print("  PORT-PRESERVING CONE NAT (or no NAT at all)")
        print("  -> daemon's STUN+publish-port approach should work as designed")
        verdict_ok = True
    elif cone and not preserving:
        print("  CONE NAT, NOT port-preserving")
        print("  -> daemon will publish the wrong port; bidirectional port")
        print("     confirmation is required, OR use NAT-PMP/PCP (test 04).")
        verdict_ok = False
    else:
        print("  SYMMETRIC NAT")
        print("  -> external port differs per destination, so STUN-derived port")
        print("     is meaningless to a third party. Direct hole-punch is")
        print("     mathematically infeasible against a non-cone peer; you need")
        print("     a relay (TURN-style VPS) or both peers behind preserving NATs.")
        verdict_ok = False

    if failures:
        print()
        print(f"  ({len(failures)} probe(s) failed; verdict based on the rest)")

    sys.exit(0 if verdict_ok else 1)


if __name__ == "__main__":
    main()
