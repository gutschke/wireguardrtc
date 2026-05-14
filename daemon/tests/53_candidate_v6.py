#!/usr/bin/env python3
# 53_candidate_v6.py — V6.D3: discover_local_candidates must surface
# IPv6 candidates from STUN, not just IPv4.
#
# The stun_provider seam now returns a list of (family, ip) tuples
# (the new dual-stack helper get_public_ips_all signature) rather
# than a flat list of v4 strings.  Old tests that pass a flat list
# of v4 strings should still work — the candidate enumerator must
# accept either shape for back-compat.

import asyncio
import importlib.machinery
import importlib.util
import os
import socket
import sys
import types

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
loader = importlib.machinery.SourceFileLoader(
    "wgrtc", os.path.join(REPO, "wireguardrtc"))
spec = importlib.util.spec_from_loader("wgrtc", loader)
wgrtc = importlib.util.module_from_spec(spec)
loader.exec_module(wgrtc)


def gcfg(public_ip=None, advertise=None, suppress=None,
         stun_servers=("stun-a", "stun-b")):
    return types.SimpleNamespace(
        public_ip=public_ip,
        stun_servers=list(stun_servers),
        stun_strict=False,
        advertise_interfaces=list(advertise or []),
        suppress_interfaces=list(suppress or []),
    )


def _run_discover(global_config, stun_result):
    """Run discover_local_candidates with synthetic providers."""
    async def iface_p(): return []
    async def default_p(): return None
    async def stun_p(servers, state): return stun_result
    return asyncio.run(wgrtc.discover_local_candidates(
        global_config, 51820,
        own_wg_ifaces=set(),
        iface_addrs_provider=iface_p,
        default_iface_provider=default_p,
        stun_provider=stun_p,
    ))


pass_n = fail_n = 0
def expect(desc, ok, msg=""):
    global pass_n, fail_n
    if ok:
        print(f"  PASS [{desc}]")
        pass_n += 1
    else:
        print(f"  FAIL [{desc}] {msg}")
        fail_n += 1


# ─── Back-compat: legacy v4-flat-list stun_provider ───────────────

cands = _run_discover(
    gcfg(),
    stun_result=["203.0.113.5"],   # legacy v4-only flat list
)
ips = [c["ip"] for c in cands]
expect("legacy-v4-flat-list still produces a candidate",
       "203.0.113.5" in ips,
       f"got {ips}")


# ─── New: stun_provider returns (family, ip) tuples ────────────────

cands = _run_discover(
    gcfg(),
    stun_result=[(socket.AF_INET, "203.0.113.5")],
)
ips = [c["ip"] for c in cands]
expect("v4-tuple form produces the same candidate",
       "203.0.113.5" in ips,
       f"got {ips}")


# ─── V6.D3 core: v6 STUN result becomes a candidate ───────────────

cands = _run_discover(
    gcfg(),
    stun_result=[(socket.AF_INET6, "2001:db8::5")],
)
ips = [c["ip"] for c in cands]
expect("v6 STUN-tuple produces a v6 candidate",
       "2001:db8::5" in ips,
       f"got {ips}")


# ─── Dual-stack: both families end up in the ranked list ──────────

cands = _run_discover(
    gcfg(),
    stun_result=[
        (socket.AF_INET, "203.0.113.5"),
        (socket.AF_INET6, "2001:db8::5"),
    ],
)
ips = [c["ip"] for c in cands]
expect("dual-stack STUN puts both families on the wire",
       "203.0.113.5" in ips and "2001:db8::5" in ips,
       f"got {ips}")


# ─── Eligibility: v6 link-local must be dropped ───────────────────

cands = _run_discover(
    gcfg(),
    stun_result=[
        (socket.AF_INET6, "fe80::1"),         # link-local — drop
        (socket.AF_INET6, "::1"),             # loopback — drop
        (socket.AF_INET6, "ff02::1"),         # multicast — drop
        (socket.AF_INET6, "2001:db8::1"),     # GUA — keep
    ],
)
ips = [c["ip"] for c in cands]
expect("v6 link-local/loopback/multicast filtered out",
       "fe80::1" not in ips and "::1" not in ips
       and "ff02::1" not in ips,
       f"got {ips}")
expect("v6 GUA passes the eligibility filter",
       "2001:db8::1" in ips,
       f"got {ips}")


# ─── PublicIp dual-stack: comma-separated covers both families ────

cands = _run_discover(
    gcfg(public_ip="203.0.113.5, 2001:db8::5"),
    stun_result=[],
)
ips = [c["ip"] for c in cands]
expect("PublicIp comma-separated yields both family candidates",
       "203.0.113.5" in ips and "2001:db8::5" in ips,
       f"got {ips}")


print()
print(f"summary: {pass_n} passed, {fail_n} failed")
sys.exit(0 if fail_n == 0 else 1)
