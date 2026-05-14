#!/usr/bin/env python3
# 54_iface_v6.py — V6.D4: enumerate locally-configured IPv6
# addresses so the daemon can advertise them as LAN candidates
# alongside the v4 ones.
#
# The shell-out path uses `ip -6 -o addr show`.  The pure-stdlib
# fallback reads `/proc/net/if_inet6`.  Both should:
#   - return [(iface, ip_str), ...] with bare v6 strings (no
#     brackets, no /prefix)
#   - drop link-local (fe80::/10), loopback (::1), and v4-mapped
#   - keep GUA (2000::/3) and ULA (fc00::/7)

import asyncio
import importlib.machinery
import importlib.util
import os
import sys
import types

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
loader = importlib.machinery.SourceFileLoader(
    "wgrtc", os.path.join(REPO, "wireguardrtc"))
spec = importlib.util.spec_from_loader("wgrtc", loader)
wgrtc = importlib.util.module_from_spec(spec)
loader.exec_module(wgrtc)


pass_n = fail_n = 0
def expect(desc, ok, msg=""):
    global pass_n, fail_n
    if ok:
        print(f"  PASS [{desc}]")
        pass_n += 1
    else:
        print(f"  FAIL [{desc}] {msg}")
        fail_n += 1


# ─── enumerator exists ────────────────────────────────────────────

expect("_enumerate_iface_addrs_v6 exists",
       hasattr(wgrtc, "_enumerate_iface_addrs_v6"),
       "")


# ─── stdlib fallback parses /proc/net/if_inet6 ────────────────────

if hasattr(wgrtc, "_parse_proc_if_inet6"):
    # 26002a8ce9b1c00000000000000005f0 03 40 00 00     eth0
    #                                     ^ scope: 00 global, 20 link, 10 host
    sample = (
        "26002a8ce9b1c00000000000000005f0 03 40 00 00     eth0\n"
        "fe80000000000000022300fffe0a0b0c 03 40 20 80     eth0\n"
        "00000000000000000000000000000001 01 80 10 80       lo\n"
        "fd1234ab00000000111122223333abcd 03 40 00 80     eth0\n"
    )
    addrs = wgrtc._parse_proc_if_inet6(sample)
    ips = [ip for (_, ip) in addrs]
    expect("proc parser keeps GUA",
           any("2600:2a8c" in ip for ip in ips),
           f"got {ips}")
    expect("proc parser keeps ULA",
           any(ip.startswith("fd12:34ab:") for ip in ips),
           f"got {ips}")
    expect("proc parser drops link-local",
           not any(ip.startswith("fe80:") for ip in ips),
           f"got {ips}")
    expect("proc parser drops loopback",
           "::1" not in ips,
           f"got {ips}")
else:
    print("  SKIP [_parse_proc_if_inet6 not yet defined]")


# ─── discover_local_candidates accepts a v6 iface provider ────────

def gcfg(public_ip=None):
    return types.SimpleNamespace(
        public_ip=public_ip, stun_servers=[], stun_strict=False,
        advertise_interfaces=[], suppress_interfaces=[],
    )

async def _run():
    async def iface_v4(): return [("eth0", "10.0.0.1")]
    async def iface_v6(): return [("eth0", "2001:db8::5"),
                                    ("eth0", "fd12::5")]
    async def default_p(): return "eth0"
    async def stun_p(_, __): return []
    return await wgrtc.discover_local_candidates(
        gcfg(), 51820,
        own_wg_ifaces=set(),
        iface_addrs_provider=iface_v4,
        iface_addrs_v6_provider=iface_v6,
        default_iface_provider=default_p,
        stun_provider=stun_p,
    )

try:
    cands = asyncio.run(_run())
    ips = [c["ip"] for c in cands]
    expect("v6 iface addrs surface as candidates",
           "2001:db8::5" in ips and "fd12::5" in ips,
           f"got {ips}")
    expect("v4 iface addrs still surface",
           "10.0.0.1" in ips,
           f"got {ips}")
except TypeError as e:
    expect("discover_local_candidates accepts iface_addrs_v6_provider",
           False, str(e))


print()
print(f"summary: {pass_n} passed, {fail_n} failed")
sys.exit(0 if fail_n == 0 else 1)
