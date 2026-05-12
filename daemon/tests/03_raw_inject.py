#!/usr/bin/env python3
"""
The single most load-bearing test.

The daemon assumes:
  (a) we can construct a raw UDP packet with src_port = X and have the kernel
      send it onto the wire,
  (b) doing so creates conntrack/NAT state such that return traffic to port X
      is delivered to a userspace socket that BOUND port X *after* the raw
      send, sharing the same NAT mapping the kernel WG module would use.

We test (a) and (b) on a *test port* — never the real WG listen port — using
a public STUN server as the destination, because:
  * STUN servers are designed to receive unsolicited UDP and respond.
  * Their response (XOR-MAPPED-ADDRESS) tells us the external IP/port the
    response was returned to. If that's our test port, the NAT mapping is
    intact and the round trip works end-to-end.
  * It's exactly one request / one response.

Failure modes this test detects:
  - raw socket creation refused (no CAP_NET_RAW)
  - egress filter / ip_local_port_range / rp_filter dropping the spoofed-port
    packet
  - NAT does not preserve the source port (so the response goes elsewhere)
  - conntrack is disabled / not loaded (informational; doesn't fail the run)

Usage:  sudo ./03_raw_inject.py
        sudo ./03_raw_inject.py --port 51899 --server stun.l.google.com:19302
"""

import argparse
import os
import socket
import struct
import subprocess
import sys
import time

MAGIC_COOKIE = 0x2112A442


def find_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def stun_request_bytes():
    txid = os.urandom(12)
    return txid, struct.pack("!HHL12s", 0x0001, 0, MAGIC_COOKIE, txid)


def parse_stun_xor_mapped(data, expected_txid):
    if len(data) < 20:
        return None
    msg_type, msg_len, magic, txid = struct.unpack("!HHL12s", data[:20])
    if msg_type != 0x0101 or magic != MAGIC_COOKIE or txid != expected_txid:
        return None
    offset = 20
    end = 20 + msg_len
    while offset + 4 <= end:
        atype, alen = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4
        if atype == 0x0020 and alen >= 8:
            family = data[offset + 1]
            if family == 0x01:
                xport = struct.unpack("!H", data[offset + 2:offset + 4])[0]
                xip = struct.unpack("!L", data[offset + 4:offset + 8])[0]
                ext_port = xport ^ (MAGIC_COOKIE >> 16)
                ext_ip = socket.inet_ntoa(struct.pack("!L", xip ^ MAGIC_COOKIE))
                return ext_ip, ext_port
        offset += alen + ((4 - (alen % 4)) % 4)
    return None


def build_ip_udp_packet(src_port, dst_ip, dst_port, payload):
    # IP header. tot_len in network byte order on Linux. Checksum left 0
    # (kernel fills it). src=0.0.0.0 (kernel fills it from routing).
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        (4 << 4) | 5,            # version=4, IHL=5
        0,                       # DSCP/ECN
        20 + 8 + len(payload),   # total length
        0,                       # ID (random per RFC 791; 0 is fine for kernel)
        0,                       # flags + frag offset
        64,                      # TTL
        socket.IPPROTO_UDP,      # protocol
        0,                       # header checksum (kernel computes)
        b"\x00\x00\x00\x00",     # src IP (kernel fills)
        socket.inet_aton(dst_ip),
    )
    # UDP header. Checksum 0 is legal for IPv4 UDP.
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
    return ip_hdr + udp_hdr + payload


def conntrack_lookup(src_port, dst_ip, dst_port):
    """Best-effort dump of matching conntrack entries. Returns lines or None."""
    try:
        out = subprocess.run(
            [
                "conntrack", "-L", "-p", "udp",
                "--orig-port-src", str(src_port),
                "--orig-port-dst", str(dst_port),
                "--dst", dst_ip,
            ],
            capture_output=True, text=True, timeout=2,
        )
        if out.returncode == 0:
            lines = [l for l in out.stdout.splitlines() if l.strip()]
            return lines
        return None
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=None,
                    help="test source port (default: random free port)")
    ap.add_argument("--server", default="stun.l.google.com:19302",
                    help="STUN server host:port to send to")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("This test needs raw-socket access (CAP_NET_RAW). Run as root or:")
        print("    sudo setcap cap_net_raw=eip $(readlink -f $(which python3))")
        sys.exit(2)

    test_port = args.port or find_free_port()
    server_host, server_port_str = args.server.rsplit(":", 1)
    server_port = int(server_port_str)
    try:
        server_ip = socket.gethostbyname(server_host)
    except socket.gaierror as e:
        print(f"DNS lookup failed for {server_host}: {e}")
        sys.exit(2)

    print(f"Test port:    {test_port}")
    print(f"STUN server:  {server_host} ({server_ip}):{server_port}")
    print()

    # Step 1: bind a kernel UDP socket on test_port. This is a faithful
    # stand-in for the kernel WG module's exclusive bind: it will receive
    # any return traffic to test_port that the NAT maps to us.
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        listener.bind(("0.0.0.0", test_port))
    except OSError as e:
        print(f"FAIL: could not bind UDP socket to test port {test_port}: {e}")
        print("      pick a different port with --port")
        sys.exit(2)
    listener.settimeout(3.0)
    print(f"[1] kernel UDP socket bound to 0.0.0.0:{test_port}")

    # Step 2: build STUN request as the UDP payload, then a raw IP+UDP packet
    # with src_port = test_port. The raw socket sends it onto the wire
    # bypassing local bind enforcement.
    txid, stun_payload = stun_request_bytes()
    packet = build_ip_udp_packet(test_port, server_ip, server_port, stun_payload)

    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        raw.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        print("FAIL: cannot create AF_INET/SOCK_RAW (need CAP_NET_RAW)")
        listener.close()
        sys.exit(2)

    raw.sendto(packet, (server_ip, server_port))
    raw.close()
    print(f"[2] raw-injected UDP {test_port} -> {server_ip}:{server_port} "
          f"(payload {len(stun_payload)} B STUN binding request)")

    # Step 3: peek at conntrack (informational; not fatal if missing).
    time.sleep(0.2)
    ct = conntrack_lookup(test_port, server_ip, server_port)
    if ct is None:
        print("[3] conntrack: command not available or no matching entry")
        print("    install with: sudo apt install conntrack")
    elif not ct:
        print("[3] conntrack: NO matching entry found")
        print("    (this can be normal if conntrack-udp tracking is disabled,")
        print("     or if your kernel routes the packet outside the netns)")
    else:
        print(f"[3] conntrack: {len(ct)} matching entry/entries")
        for line in ct:
            print(f"    {line}")

    # Step 4: try to receive the STUN response on our kernel-bound socket.
    # If we receive it, that's positive proof of the whole pipeline:
    #   raw inject -> wire -> NAT mapping -> server -> NAT reverse -> our port
    print(f"[4] waiting up to 3 s for STUN response on port {test_port}...")
    try:
        data, src = listener.recvfrom(2048)
    except socket.timeout:
        print("    NO RESPONSE")
        print()
        print("VERDICT: raw-inject + return-via-bound-socket pipeline DOES NOT WORK")
        print("on this network. Possible causes:")
        print("  * egress filtering of source-spoofed packets (rp_filter / ufw / cloud SG)")
        print("  * NAT not preserving the source port (run test 01 to confirm)")
        print("  * outbound UDP blocked")
        print("  * STUN server unreachable")
        listener.close()
        sys.exit(1)

    parsed = parse_stun_xor_mapped(data, txid)
    listener.close()
    if parsed is None:
        print(f"    response received from {src} but failed to parse")
        sys.exit(1)
    ext_ip, ext_port = parsed
    print(f"    response received: external mapping is {ext_ip}:{ext_port}")
    print()
    if ext_port == test_port:
        print("VERDICT: PASS")
        print("  Raw inject from a kernel-bound source port works AND the upstream")
        print("  NAT (if any) preserved the port AND return traffic reached the")
        print("  socket. The daemon's mechanism is sound on this network.")
        sys.exit(0)
    else:
        print(f"VERDICT: PARTIAL PASS")
        print(f"  Raw inject works and the round trip completes, but the NAT")
        print(f"  remapped {test_port} -> {ext_port}. The daemon would publish")
        print(f"  the wrong port to peers. NAT-PMP/PCP (test 04) or bidirectional")
        print(f"  port confirmation is needed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
