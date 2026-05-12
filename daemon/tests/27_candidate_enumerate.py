#!/usr/bin/env python3
# 27_candidate_enumerate.py — the daemon enumerates local interfaces
# + STUN reflexive addresses and
# emits a RANKED candidate list per the rule table:
#
# rank 0 PublicIp from [Global] kind=stun
# rank 10 STUN reflexive (if different) kind=stun
# rank 20 physical iface, holds default route kind=stun
# rank 30 physical iface, no default route kind=stun
# rank 40 bridge (br*/vmbr*) kind=lan
# rank 50 RFC1918 + CGNAT (100.64/10) kind=lan
# rank 60 AdvertiseInterfaces allowlist kind=mesh
#
# Hard drops:
# - loopback / link-local / multicast / unspecified / op-down
# - daemon's own active WG interface(s) (self-reference)
# - admin's [Global] SuppressInterfaces matches
# - 192.0.0.0/29 (RFC 7335 CLAT v4-over-v6 stub — Pixel cellular)
# - default-skip tunnel patterns: tun*/tap*/ppp*/tailscale*/zt*/
# gre*/ipip*/sit*/ip6tnl* (UNLESS in AdvertiseInterfaces)
#
# Tests inject the iface table + default route + STUN response so we
# don't need a real network; the production code path takes the same
# function and feeds it real data via `ip -j -4 addr show` and
# `ip -j -4 route show default`.

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


pass_n = 0
fail_n = 0
def expect(desc, actual, want):
 global pass_n, fail_n
 if actual == want:
 print(f" PASS [{desc}] -> {actual}")
 pass_n += 1
 else:
 print(f" FAIL [{desc}] expected {want!r} got {actual!r}")
 fail_n += 1


def gcfg(public_ip=None, advertise=None, suppress=None,
 stun_servers=("stun-a", "stun-b")):
 return types.SimpleNamespace(
 public_ip=public_ip,
 stun_servers=list(stun_servers),
 stun_strict=False,
 advertise_interfaces=list(advertise or []),
 suppress_interfaces=list(suppress or []),
 )


def discover(global_config, listen_port, own_wg_ifaces=None,
 iface_addrs=None, default_iface=None, stun_ips=None):
 """Test wrapper: pass synthetic iface/route/STUN data."""
 async def iface_p(): return list(iface_addrs or [])
 async def default_p(): return default_iface
 async def stun_p(servers, state): return list(stun_ips or [])
 return asyncio.run(wgrtc.discover_local_candidates(
 global_config, listen_port,
 own_wg_ifaces=set(own_wg_ifaces or []),
 iface_addrs_provider=iface_p,
 default_iface_provider=default_p,
 stun_provider=stun_p,
 ))


def ips_of(cands):
 return [c["ip"] for c in cands]


def kinds_of(cands):
 return [c["kind"] for c in cands]


# ─── Trivial cases ───────────────────────────────────────────────

print("=== trivial / common cases ===")

# Single STUN response, no PublicIp, no useful local ifaces.
# Common: typical home server behind NAT. One candidate: STUN.
r = discover(gcfg(), 51820,
 iface_addrs=[("eth0", "10.0.0.1")], # private LAN only
 default_iface="eth0",
 stun_ips=["203.0.113.5"])
expect("typical-nat-home-server",
 [(c["ip"], c["port"], c["kind"]) for c in r],
 [("203.0.113.5", 51820, "stun"),
 ("10.0.0.1", 51820, "lan")])

# PublicIp override + STUN that agrees → deduped, single candidate.
r = discover(gcfg(public_ip="203.0.113.5"), 51820,
 iface_addrs=[],
 stun_ips=["203.0.113.5"])
expect("public-ip-and-stun-agree-deduped",
 ips_of(r), ["203.0.113.5"])

# PublicIp + STUN disagree (multi-WAN) → both kept, PublicIp first.
r = discover(gcfg(public_ip="198.51.100.1"), 51820,
 iface_addrs=[],
 stun_ips=["203.0.113.5"])
expect("public-ip-and-stun-disagree-both-kept",
 ips_of(r), ["198.51.100.1", "203.0.113.5"])

# Empty everything → empty list (caller decides what to do — Step B
# already logs and skips when empty).
r = discover(gcfg(), 51820, iface_addrs=[], stun_ips=[])
expect("empty-everything-empty-list", r, [])


# ─── Hard drops ──────────────────────────────────────────────────

print()
print("=== hard drops ===")

# Loopback / link-local / multicast / unspecified.
r = discover(gcfg(), 51820,
 iface_addrs=[
 ("lo", "127.0.0.1"), # loopback
 ("eth0", "169.254.42.1"), # link-local
 ("eth1", "224.0.0.1"), # multicast — won't be a real iface IP, but defensive
 ("eth2", "0.0.0.0"), # unspecified
 ("eth3", "192.0.0.4"), # CLAT stub (RFC 7335)
 ("eth4", "203.0.113.5"), # legitimate
 ],
 stun_ips=[])
expect("hard-drops-keep-only-legitimate",
 ips_of(r), ["203.0.113.5"])

# Daemon's own active WG iface — never advertise.
r = discover(gcfg(), 51820, own_wg_ifaces=["wg0"],
 iface_addrs=[
 ("wg0", "10.99.0.1"),
 ("eth0", "203.0.113.5"),
 ])
expect("own-wg-iface-self-ref-dropped",
 ips_of(r), ["203.0.113.5"])

# SuppressInterfaces denylist.
r = discover(gcfg(suppress=["docker0", "vmnet1"]), 51820,
 iface_addrs=[
 ("docker0", "172.17.0.1"),
 ("vmnet1", "172.18.0.1"),
 ("eth0", "203.0.113.5"),
 ])
expect("suppress-list-applied",
 ips_of(r), ["203.0.113.5"])

# Default-skip tunnel patterns.
r = discover(gcfg(), 51820,
 iface_addrs=[
 ("tun0", "10.8.0.1"), # OpenVPN
 ("tap0", "10.9.0.1"), # OpenVPN tap
 ("ppp0", "192.0.2.1"), # PPPoE legacy
 ("tailscale0", "100.64.0.1"), # Tailscale (CGNAT but on tunnel iface)
 ("zt0aaaaaa", "198.51.100.1"), # ZeroTier
 ("gre0", "192.0.2.5"), # GRE
 ("sit0", "192.0.2.6"), # 6in4
 ("ipip0", "192.0.2.7"), # IPIP
 ("ip6tnl0", "192.0.2.8"), # IPv6 tunnel
 ("eth0", "203.0.113.5"), # legitimate
 ])
expect("tunnel-patterns-default-skip",
 ips_of(r), ["203.0.113.5"])


# ─── Ranking ─────────────────────────────────────────────────────

print()
print("=== ranking by rule table ===")

# Default-route iface ranks above non-default. We use 8.8.8.8 /
# 1.1.1.1 instead of RFC 5737 documentation prefixes (192.0.2/24,
# 198.51.100/24, 203.0.113/24) because Python's `ipaddress`
# correctly treats those as non-globally-routable, so the
# classifier puts them in rank 50 (private/lan) instead of 20/30.
# Real public IPs only matter as STRINGS here; we never send to them.
r = discover(gcfg(), 51820,
 iface_addrs=[
 ("eth1", "1.1.1.1"), # public, non-default
 ("eth0", "8.8.8.8"), # public, default route
 ],
 default_iface="eth0")
expect("default-route-ranks-above-non-default",
 ips_of(r), ["8.8.8.8", "1.1.1.1"])

# RFC1918 sorts AFTER public on default-route.
r = discover(gcfg(), 51820,
 iface_addrs=[
 ("eth0", "10.0.0.1"), # RFC1918
 ("eth0", "8.8.8.8"), # public on same iface
 ],
 default_iface="eth0")
expect("public-default-above-rfc1918",
 ips_of(r), ["8.8.8.8", "10.0.0.1"])

# Bridge with PUBLIC address ranks below physical-default but above
# private/RFC1918. (Bridges with private addresses go through the
# private-priority path → rank 40 too via the bridge branch, see
# next case.)
r = discover(gcfg(), 51820,
 iface_addrs=[
 ("br-lan", "1.1.1.1"), # bridge with public addr (unusual but legal)
 ("eth0", "8.8.8.8"),
 ("vmbr0", "10.0.0.1"),
 ],
 default_iface="eth0")
expect("bridge-public-below-physical-default",
 ips_of(r), ["8.8.8.8", "1.1.1.1", "10.0.0.1"])

# AdvertiseInterfaces overrides default-skip and lands at rank 60
# (mesh kind) — corp wg-mesh scenario.
r = discover(gcfg(advertise=["wg-mesh0"]), 51820,
 iface_addrs=[
 ("wg-mesh0", "10.50.0.1"),
 ("eth0", "203.0.113.5"),
 ],
 default_iface="eth0",
 stun_ips=["203.0.113.5"])
# eth0's 203.0.113.5 dedups with STUN; mesh entry comes last.
expect("advertise-list-rescues-tunnel-iface",
 [(c["ip"], c["kind"]) for c in r],
 [("203.0.113.5", "stun"), ("10.50.0.1", "mesh")])

# CGNAT (100.64.0.0/10) treated as private/lan rank 50 — kept
# (not dropped); CGNAT IPs may legitimately appear on a daemon
# behind a carrier-grade NAT.
r = discover(gcfg(), 51820,
 iface_addrs=[("eth0", "100.64.5.1")],
 default_iface="eth0")
expect("cgnat-kept-as-lan",
 [(c["ip"], c["kind"]) for c in r],
 [("100.64.5.1", "lan")])


# ─── PublicIp / STUN ordering ────────────────────────────────────

print()
print("=== PublicIp / STUN ordering ===")

# Multi-homed STUN: two distinct reflexive addresses → both at rank 10.
r = discover(gcfg(), 51820,
 iface_addrs=[],
 stun_ips=["203.0.113.5", "198.51.100.1"])
expect("multi-homed-stun-both-kept",
 ips_of(r), ["203.0.113.5", "198.51.100.1"])

# PublicIp ALWAYS first (rank 0).
r = discover(gcfg(public_ip="9.9.9.9"), 51820,
 iface_addrs=[("eth0", "10.0.0.1")],
 stun_ips=["203.0.113.5"])
expect("publicip-rank-zero-first",
 ips_of(r), ["9.9.9.9", "203.0.113.5", "10.0.0.1"])


# ─── Cap at 10 ───────────────────────────────────────────────────

print()
print("=== list cap ===")

# Pathological: many ifaces. Cap at 10. Top-ranked survive.
many_ifaces = [(f"eth{i}", f"10.0.{i}.1") for i in range(15)]
r = discover(gcfg(public_ip="9.9.9.9"), 51820,
 iface_addrs=many_ifaces,
 stun_ips=["203.0.113.5"])
expect("cap-at-10-preserves-top-ranked",
 len(r), 10)
expect("cap-at-10-publicip-survives", r[0]["ip"], "9.9.9.9")
expect("cap-at-10-stun-survives", r[1]["ip"], "203.0.113.5")


# ─── Per-peer trim integration with Step B ──────────────────────

print()
print("=== Step C + Step B per-peer trim integration ===")

# discover_local_candidates produces the FULL list; Step B's
# filter_candidates_for_peer trims per-peer. Verify the integration
# works correctly: a peer with AllowedIPs = 0.0.0.0/0 should end up
# with no candidates after the trim, even when the discovery list
# was non-trivial.
r = discover(gcfg(public_ip="9.9.9.9"), 51820,
 iface_addrs=[("eth0", "10.0.0.1")],
 stun_ips=["203.0.113.5"])
trimmed = wgrtc.filter_candidates_for_peer(r, "0.0.0.0/0")
expect("step-B-trim-on-step-C-output-deadlock-empty",
 trimmed, [])

# A peer with a narrower AllowedIPs (only 10.0.0.0/24) drops just
# the matching candidate.
trimmed = wgrtc.filter_candidates_for_peer(r, "10.0.0.0/24")
expect("step-B-trim-narrow-allowed-ips",
 ips_of(trimmed), ["9.9.9.9", "203.0.113.5"])


print()
print(f"summary: {pass_n} passed, {fail_n} failed")
sys.exit(0 if fail_n == 0 else 1)
