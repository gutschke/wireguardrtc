#!/usr/bin/env python3
"""
Probe the upstream router for NAT-PMP (RFC 6886) and PCP (RFC 6887) support.

If the gateway answers either, the daemon should *prefer* asking it for an
explicit UDP port mapping over relying on STUN-derived address publication.
An explicit mapping is strictly more reliable: it survives non-port-preserving
NATs, and it doesn't depend on the timing of "raw inject before peer arrives".

The probe is read-only:
  * NAT-PMP "external IP" request — no mapping is created
  * PCP MAP request with lifetime=0 (i.e., a query, not an actual mapping)

Usage:  ./04_natpmp_pcp.py
        ./04_natpmp_pcp.py --gateway 192.168.1.1
"""

import argparse
import os
import socket
import struct
import sys
import time


def default_gateway_v4():
    """Parse /proc/net/route to find the IPv4 default gateway. Returns dotted IP or None."""
    try:
        with open("/proc/net/route") as f:
            f.readline()  # header
            for line in f:
                parts = line.split()
                if len(parts) < 4:
                    continue
                iface, dest_hex, gw_hex, flags_hex = parts[0], parts[1], parts[2], parts[3]
                if int(dest_hex, 16) == 0 and (int(flags_hex, 16) & 0x2):  # RTF_GATEWAY
                    gw_int = int(gw_hex, 16)
                    return socket.inet_ntoa(struct.pack("<L", gw_int)), iface
    except FileNotFoundError:
        pass
    return None, None


def probe_natpmp(gateway, timeout=2.0):
    """Send NAT-PMP v0 'public address request' (op=0). Returns (ok, msg)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(b"\x00\x00", (gateway, 5351))  # version=0, opcode=0
        data, _ = s.recvfrom(64)
    except socket.timeout:
        return False, "no response (gateway likely doesn't speak NAT-PMP)"
    except OSError as e:
        return False, f"send failed: {e}"
    finally:
        s.close()

    if len(data) < 12:
        return False, f"response too short ({len(data)} bytes)"
    version, opcode, result_code = struct.unpack("!BBH", data[:4])
    sec_since_epoch = struct.unpack("!L", data[4:8])[0]
    ext_ip = socket.inet_ntoa(data[8:12])
    if version != 0:
        return False, f"non-NAT-PMP version {version} in reply"
    if opcode != 128:  # response = 128 + request opcode
        return False, f"unexpected opcode {opcode} in reply"
    if result_code != 0:
        return False, f"NAT-PMP error code {result_code}"
    return True, f"NAT-PMP v0 reply: external IP {ext_ip} (router uptime {sec_since_epoch}s)"


def probe_pcp(gateway, timeout=2.0):
    """Send a PCP ANNOUNCE request. Returns (ok, msg).

    ANNOUNCE has opcode 0 with no body and triggers a server-state response;
    it doesn't create or modify mappings, so it's safe as a probe.
    """
    # PCP request header (RFC 6887 §7.1):
    #   version(1)=2, R(1)=0+opcode(7)=0, reserved(2)=0, lifetime(4)=0,
    #   client_ip(16)=:: (any)
    # Total 24 bytes.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        # Bind so the kernel picks a source — PCP responses go back to our socket.
        s.bind(("0.0.0.0", 0))
        # PCP requires an IPv4-mapped-IPv6 client address; we use 0::0 (any).
        request = struct.pack(
            "!BBH I 16s",
            2, 0, 0,           # version, R+opcode (ANNOUNCE), reserved
            0,                 # lifetime
            b"\x00" * 16,      # client IP (let server use packet src)
        )
        s.sendto(request, (gateway, 5351))
        data, _ = s.recvfrom(1100)
    except socket.timeout:
        return False, "no response (gateway likely doesn't speak PCP)"
    except OSError as e:
        return False, f"send failed: {e}"
    finally:
        s.close()

    if len(data) < 24:
        return False, f"response too short ({len(data)} bytes)"
    version, r_opcode, _, result_code = struct.unpack("!BBHB", data[:5])
    if version != 2:
        return False, f"non-PCP version {version} in reply (got NAT-PMP server?)"
    is_response = bool(r_opcode & 0x80)
    opcode = r_opcode & 0x7F
    if not is_response:
        return False, "reply is not marked as a response"
    return True, f"PCP v2 reply: opcode={opcode}, result_code={result_code} (0 = success)"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gateway", default=None,
                    help="probe this address instead of the auto-detected default gateway")
    args = ap.parse_args()

    if args.gateway:
        gateway, iface = args.gateway, "?"
    else:
        gateway, iface = default_gateway_v4()
        if gateway is None:
            print("Could not determine default gateway from /proc/net/route.")
            print("Pass --gateway <ip> manually.")
            sys.exit(2)

    print(f"Probing gateway: {gateway} (via {iface})")
    print()

    print("[1] NAT-PMP (RFC 6886)")
    ok_pmp, msg = probe_natpmp(gateway)
    print(f"    {'OK  ' if ok_pmp else 'FAIL'}  {msg}")
    print()

    print("[2] PCP (RFC 6887)")
    ok_pcp, msg = probe_pcp(gateway)
    print(f"    {'OK  ' if ok_pcp else 'FAIL'}  {msg}")
    print()

    if ok_pmp or ok_pcp:
        print("VERDICT: gateway supports automatic port mapping.")
        print("  Daemon should prefer this over STUN-derived port publication on this")
        print("  network. The mapping protocol returns the actual external port the")
        print("  router will forward, eliminating the port-preservation guesswork.")
        sys.exit(0)
    else:
        print("VERDICT: no NAT-PMP / PCP support detected.")
        print("  The daemon must rely on STUN + raw-inject + (optionally) bidirectional")
        print("  port confirmation on this network.")
        sys.exit(1)


if __name__ == "__main__":
    main()
