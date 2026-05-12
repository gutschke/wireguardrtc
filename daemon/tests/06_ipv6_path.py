#!/usr/bin/env python3
"""
Probe IPv6 reachability for direct peer-to-peer.

If both peers have working global IPv6, NAT traversal becomes a non-issue:
each peer announces its own (v6_addr, listen_port) and the kernel WG modules
talk directly. The daemon's whole hole-punching apparatus is unnecessary.

This test answers: "could this host participate in a v6-direct WG tunnel
without help from the daemon?"

Checks:
  1. Do we have a global-scope IPv6 address (not just link-local / ULA)?
  2. Can we resolve AAAA records?
  3. Can we send a UDP packet to a known v6 address and get a response back?
  4. Can we reach a v6 STUN server (for symmetric-discovery purposes)?

Usage:  ./06_ipv6_path.py
"""

import argparse
import ipaddress
import os
import socket
import struct
import sys
import time

MAGIC_COOKIE = 0x2112A442

# Cloudflare's public DNS / STUN endpoints over v6.
DNS6 = ("2606:4700:4700::1111", 53)
STUN6 = "stun.cloudflare.com:3478"


def list_global_v6():
    """Return list of global-scope IPv6 addresses on this host (excludes link-local, loopback, ULA)."""
    out = []
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET6)
    except socket.gaierror:
        infos = []
    seen = set()
    for fam, _, _, _, sockaddr in infos:
        addr = sockaddr[0].split("%")[0]  # strip zone id
        if addr in seen:
            continue
        seen.add(addr)
        try:
            ip = ipaddress.IPv6Address(addr)
        except ValueError:
            continue
        if ip.is_global:
            out.append(str(ip))
    # Fall back to scanning the routing socket via /proc if the above missed anything.
    try:
        with open("/proc/net/if_inet6") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 6:
                    continue
                hex_addr = parts[0]
                addr = ":".join(hex_addr[i:i+4] for i in range(0, 32, 4))
                try:
                    ip = ipaddress.IPv6Address(addr)
                except ValueError:
                    continue
                if ip.is_global and str(ip) not in seen:
                    seen.add(str(ip))
                    out.append(str(ip))
    except FileNotFoundError:
        pass
    return out


def aaaa_lookup(host):
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET6, socket.SOCK_DGRAM)
    except socket.gaierror as e:
        return None, str(e)
    return [info[4][0] for info in infos], None


def stun_v6(server, timeout=2.5):
    host, port = server.rsplit(":", 1)
    port = int(port)
    addrs, err = aaaa_lookup(host)
    if not addrs:
        return False, f"no AAAA for {host}: {err}"
    server_ip = addrs[0]

    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        txid = os.urandom(12)
        request = struct.pack("!HHL12s", 0x0001, 0, MAGIC_COOKIE, txid)
        s.sendto(request, (server_ip, port))
        data, src = s.recvfrom(2048)
    except socket.timeout:
        return False, f"timeout sending to [{server_ip}]:{port}"
    except OSError as e:
        return False, f"send failed: {e}"
    finally:
        s.close()
    if len(data) < 20:
        return False, "STUN response too short"
    msg_type, _, magic, _ = struct.unpack("!HHL12s", data[:20])
    if msg_type != 0x0101 or magic != MAGIC_COOKIE:
        return False, f"unexpected STUN reply (type=0x{msg_type:04x})"
    return True, f"got STUN reply over IPv6 from [{server_ip}]:{port}"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stun", default=STUN6, help="IPv6 STUN server host:port")
    args = ap.parse_args()

    print("[1] Global IPv6 addresses on this host")
    addrs = list_global_v6()
    if addrs:
        for a in addrs:
            print(f"    {a}")
    else:
        print("    none — IPv6 is unavailable or only ULA/link-local")
    print()

    print("[2] AAAA resolution sanity check (one.one.one.one)")
    res, err = aaaa_lookup("one.one.one.one")
    if res:
        print(f"    {res}")
    else:
        print(f"    FAIL: {err}")
    print()

    print("[3] UDP reachability test (DNS query to Cloudflare v6)")
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.settimeout(2.5)
    try:
        # minimal DNS query for "." NS — small, valid, public DNS responds.
        query = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x00\x00\x02\x00\x01"
        s.sendto(query, DNS6)
        data, src = s.recvfrom(1500)
        print(f"    OK   received {len(data)} bytes from {src[0]}")
        v6_udp_ok = True
    except socket.timeout:
        print("    FAIL no response — outbound UDPv6 may be blocked or no v6 route")
        v6_udp_ok = False
    except OSError as e:
        print(f"    FAIL {e}")
        v6_udp_ok = False
    finally:
        s.close()
    print()

    print(f"[4] STUN over IPv6 ({args.stun})")
    stun_ok, stun_msg = stun_v6(args.stun)
    print(f"    {'OK  ' if stun_ok else 'FAIL'}  {stun_msg}")
    print()

    if addrs and v6_udp_ok:
        print("VERDICT: IPv6 is usable for direct peer-to-peer WireGuard.")
        print("  Daemon should detect peers' IPv6 reachability and skip hole-punching")
        print("  entirely when both ends have global v6.")
        sys.exit(0)
    else:
        print("VERDICT: IPv6 not usable here — daemon needs the v4 NAT-traversal path.")
        sys.exit(1)


if __name__ == "__main__":
    main()
