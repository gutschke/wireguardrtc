#!/usr/bin/env python3
"""
Verify that the kernel WireGuard module exclusively binds its UDP listen port,
i.e. that we cannot share it from userspace via SO_REUSEADDR / SO_REUSEPORT.

This confirms (or refutes) the design rationale in section 3.3 of the doc:
"the wireguard-linux kernel module requests an exclusive socket bind, so
standard userspace applications cannot use SO_REUSEPORT to share it".

If this test ever shows that we *can* bind alongside the WG module, we have
a much cleaner alternative to raw-socket injection.

Usage: ./02_port_bind.py [--port N]    explicit port instead of wg discovery
       ./02_port_bind.py                discover via `wg show` (needs CAP_NET_ADMIN
                                       to read listen-port; if unavailable
                                       the test asks you to pass --port)

Doesn't send any packets. Opens and immediately closes test sockets.
"""

import argparse
import socket
import subprocess
import sys


def have_cmd(cmd):
    try:
        subprocess.run([cmd, "--version"], capture_output=True, check=False, timeout=2)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def discover_wg_ports():
    """Return list of (interface, listen_port) tuples from `wg show`."""
    if not have_cmd("wg"):
        print("  wg command not found — install: sudo apt install wireguard-tools")
        return []
    try:
        ifaces_out = subprocess.run(
            ["wg", "show", "interfaces"],
            capture_output=True, text=True, check=True, timeout=2,
        ).stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"  `wg show interfaces` failed: {e.stderr}")
        return []
    if not ifaces_out:
        return []
    out = []
    for iface in ifaces_out.split():
        try:
            port_str = subprocess.run(
                ["wg", "show", iface, "listen-port"],
                capture_output=True, text=True, check=True, timeout=2,
            ).stdout.strip()
            if port_str:
                out.append((iface, int(port_str)))
        except (subprocess.CalledProcessError, ValueError):
            pass
    return out


def try_bind(port, with_reuseaddr=False, with_reuseport=False, family=socket.AF_INET):
    """Try to bind a UDP socket to `port`. Returns (ok, errno_or_zero, errstr)."""
    s = socket.socket(family, socket.SOCK_DGRAM)
    try:
        if with_reuseaddr:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if with_reuseport and hasattr(socket, "SO_REUSEPORT"):
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        addr = ("0.0.0.0", port) if family == socket.AF_INET else ("::", port)
        s.bind(addr)
        return True, 0, ""
    except OSError as e:
        return False, e.errno, str(e)
    finally:
        s.close()


def probe_port(port, label):
    print(f"\n[{label}] port {port}")
    plain_ok, _, plain_err = try_bind(port)
    reuse_ok, _, reuse_err = try_bind(port, with_reuseaddr=True, with_reuseport=True)
    if not plain_ok and not reuse_ok:
        print(f"  plain bind:           FAILED ({plain_err})")
        print(f"  REUSEADDR+REUSEPORT:  FAILED ({reuse_err})")
        print("  -> port is held exclusively. Confirms raw-inject is the only")
        print("     way to source a packet from this port.")
        return "exclusive"
    if plain_ok:
        print("  plain bind:           SUCCEEDED")
        print("  -> nothing is using this port (or this isn't a WG port).")
        print("     If this was supposed to be a WG listen port, the daemon")
        print("     wouldn't even be needed for hole punching.")
        return "free"
    print(f"  plain bind:           FAILED ({plain_err})")
    print("  REUSEADDR+REUSEPORT:  SUCCEEDED")
    print("  -> the holder uses REUSEPORT, so we can share the port without")
    print("     raw-socket injection. This would simplify the daemon massively.")
    return "shareable"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=None,
                    help="probe this port instead of discovering WG interfaces")
    args = ap.parse_args()

    if args.port is not None:
        result = probe_port(args.port, "manual")
        sys.exit(0 if result == "exclusive" else 1)

    wg_ports = discover_wg_ports()
    if not wg_ports:
        print("No WireGuard interfaces discovered (or insufficient privilege).")
        print("Pass --port <N> to probe a specific port instead.")
        print()
        print("If you want to probe a WG port specifically, find it with:")
        print("    sudo wg show all listen-port")
        sys.exit(2)

    results = []
    for iface, port in wg_ports:
        results.append((iface, port, probe_port(port, iface)))

    print()
    print("Summary:")
    overall_ok = True
    for iface, port, status in results:
        marker = "OK" if status == "exclusive" else "INVESTIGATE"
        print(f"  {iface:12s}  port {port:>5d}  ->  {status:12s}  [{marker}]")
        if status != "exclusive":
            overall_ok = False

    sys.exit(0 if overall_ok else 1)


if __name__ == "__main__":
    main()
