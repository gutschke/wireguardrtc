#!/usr/bin/env python3
"""
Read-only inspection of WireGuard state and what wake_tunnel() would do.

The daemon's `wake_tunnel(iface, peer_pub)` reads `wg show <iface> allowed-ips`
and pings the first non-`(none)` allowed-ip to force the kernel to fire a
handshake. This test surveys what that decision would be for each peer
*without* sending any packet, so an operator can spot bad cases (no IPv4
allowed-ip, IPv6-only peer, /0 catchall, etc.) before turning the daemon on.

This test does not modify any state and does not send any packet. It only
reads `wg show` output.

Usage:  sudo ./07_wake_observe.py
"""

import argparse
import ipaddress
import os
import subprocess
import sys
import time


def run_wg(args):
    try:
        out = subprocess.run(["wg"] + args, capture_output=True, text=True, timeout=3)
    except FileNotFoundError:
        print("FAIL: `wg` command not found. Install: sudo apt install wireguard-tools")
        sys.exit(2)
    return out


def list_interfaces():
    out = run_wg(["show", "interfaces"])
    if out.returncode != 0:
        print(f"`wg show interfaces` failed: {out.stderr.strip()}")
        sys.exit(2)
    return out.stdout.split()


def get_peer_table(iface, field):
    """Return dict { peer_pub: rest_of_line } for `wg show <iface> <field>`."""
    out = run_wg(["show", iface, field])
    if out.returncode != 0:
        return {}
    table = {}
    for line in out.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            table[parts[0]] = parts[1]
        elif len(parts) == 1:
            table[parts[0]] = ""
    return table


def pick_wake_target(allowed_ips_str):
    """Return (chosen_ip_or_None, reason, kind). Mirrors what wake_tunnel should pick.

    `kind` is one of: "v4_host", "v4_net", "v6_host", "v6_net", "catchall_bug",
    "none", so the caller can categorise the issue.

    Heuristic preference:
      1. an IPv4 /32 (or any IPv4 host inside a narrower-than-/0 net)
      2. an IPv6 /128 (or first host inside a narrower-than-/0 v6 net)
      3. for /0 catchall: report as a known-bug case — current daemon's
         wake_tunnel pings parts[1].split('/')[0] which yields '0.0.0.0',
         which Linux quietly remaps to localhost. That does NOT route via
         wg<N> and so does NOT trigger a handshake.
      4. otherwise: nothing
    """
    if not allowed_ips_str or allowed_ips_str.strip() == "(none)":
        return None, "no allowed-ips configured", "none"

    # `wg show <iface> allowed-ips` separates IPs by whitespace, not commas.
    # Some scripted output formats use commas, so accept either.
    candidates = [c.strip() for c in allowed_ips_str.replace(",", " ").split() if c.strip()]
    v4_host, v4_net = [], []
    v6_host, v6_net = [], []
    has_catchall = False
    for c in candidates:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if net.prefixlen == 0:
            has_catchall = True
            continue
        if isinstance(net, ipaddress.IPv4Network):
            (v4_host if net.prefixlen == 32 else v4_net).append(net)
        else:
            (v6_host if net.prefixlen == 128 else v6_net).append(net)

    if v4_host:
        return str(v4_host[0].network_address), f"IPv4 /32 host: {v4_host[0]}", "v4_host"
    if v4_net:
        net = v4_net[0]
        hosts = list(net.hosts())
        host = hosts[0] if hosts else net.network_address
        return str(host), f"first host inside IPv4 net {net} -> {host}", "v4_net"
    if v6_host:
        return str(v6_host[0].network_address), f"IPv6 /128 host: {v6_host[0]}", "v6_host"
    if v6_net:
        net = v6_net[0]
        hosts = list(net.hosts())
        host = hosts[0] if hosts else net.network_address
        return str(host), f"first host inside IPv6 net {net} -> {host}", "v6_net"
    if has_catchall:
        return None, ("/0 catchall route only — current daemon would ping '0.0.0.0', "
                      "which Linux remaps to localhost and does NOT trigger a wg handshake. "
                      "Need SO_BINDTODEVICE-style wake, or skip wake for these peers"), "catchall_bug"
    return None, "no usable host derivable from allowed-ips", "none"


def fmt_age(last_handshake_unix):
    if last_handshake_unix == 0:
        return "never"
    age = time.time() - last_handshake_unix
    if age < 60:
        return f"{age:.0f}s ago"
    if age < 3600:
        return f"{age/60:.1f}min ago"
    return f"{age/3600:.1f}h ago"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=None,
                    help="path to wireguardrtc.conf (for cross-checking ActivePeers / DnsRoaming)")
    args = ap.parse_args()

    interfaces = list_interfaces()
    if not interfaces:
        print("No WireGuard interfaces present.")
        sys.exit(2)

    issues = 0
    for iface in interfaces:
        print(f"=== {iface} ===")
        listen_port = run_wg(["show", iface, "listen-port"]).stdout.strip()
        print(f"  listen-port: {listen_port or '(unknown)'}")
        endpoints = get_peer_table(iface, "endpoints")
        allowed = get_peer_table(iface, "allowed-ips")
        handshakes = get_peer_table(iface, "latest-handshakes")
        keepalive = get_peer_table(iface, "persistent-keepalive")

        all_peers = sorted(set(endpoints) | set(allowed) | set(handshakes))
        if not all_peers:
            print("  (no peers configured)")
            print()
            continue

        for peer in all_peers:
            short = peer[:12] + "..."
            ep = endpoints.get(peer, "(none)")
            ai = allowed.get(peer, "(none)")
            try:
                hs_unix = int(handshakes.get(peer, "0").strip() or "0")
            except ValueError:
                hs_unix = 0
            ka = keepalive.get(peer, "off")

            target, reason, kind = pick_wake_target(ai)
            dormant = (ep.strip() in ("(none)", "")) and hs_unix == 0
            print(f"  peer  {short}")
            print(f"    endpoint:        {ep}")
            print(f"    allowed-ips:     {ai}")
            print(f"    last handshake:  {fmt_age(hs_unix)}")
            print(f"    keepalive:       {ka}")
            print(f"    wake target:     {target if target else '(none)'} — {reason}")
            if dormant:
                print(f"    CLASS: passive — no endpoint, never handshook. Daemon should")
                print(f"           NOT include in ActivePeers (no one to signal). It can")
                print(f"           still RECEIVE an offer if this peer comes online.")
            elif kind == "catchall_bug":
                print(f"    CLASS: active /0 catchall — current daemon's wake is BROKEN here.")
                issues += 1
            elif target is None:
                print(f"    CLASS: active but no wake target — wake_tunnel is a no-op.")
                issues += 1
            else:
                print(f"    CLASS: active, wake target derivable ({kind}).")
            if not dormant and ka in ("off", "0", "0 (off)"):
                print(f"    HINT: no PersistentKeepalive — NAT mappings will expire on idle.")
                print(f"          Recommend `PersistentKeepalive = 25` for NATed peers.")
            print()

    if issues:
        print(f"{issues} ACTIVE peer(s) have a broken or missing wake target.")
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
