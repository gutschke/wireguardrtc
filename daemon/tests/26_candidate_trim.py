#!/usr/bin/env python3
# 26_candidate_trim.py — verifies the daemon's sender-side per-peer
# candidate trim (,
#
#
# The trim happens BEFORE encryption in `signal_peer` and drops any
# candidate whose IP falls inside that peer's `AllowedIPs`. Using
# such an IP as Endpoint would deadlock kernel-WG bringup: the peer's
# kernel would route handshake packets back into the tunnel that
# needs the handshake to come up. The receiver-side check (Step A)
# is defense-in-depth on top of this — sender pre-trims so a
# misconfigured / pre-Step-A-vintage receiver still doesn't get
# served a deadlock candidate.
#
# Also exercises the GlobalConfig parsing for the new
# [Global] AdvertiseInterfaces / SuppressInterfaces conf knobs that
# Step C will consume.

import importlib.machinery
import importlib.util
import os
import sys
import tempfile

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


# ─── filter_candidates_for_peer ───────────────────────────────────

print("=== filter_candidates_for_peer (per-peer deadlock trim) ===")

def cands(*ips):
 return [{"ip": ip, "port": 51820, "kind": "stun"} for ip in ips]


def ips_only(cs):
 return [c["ip"] for c in cs]


# Empty AllowedIPs → no filtering, full list returned (order preserved).
expect(
 "empty-allowed-ips-passthrough",
 ips_only(wgrtc.filter_candidates_for_peer(
 cands("1.2.3.4", "5.6.7.8"), "")),
 ["1.2.3.4", "5.6.7.8"],
)

# AllowedIPs = 0.0.0.0/0 — full-tunnel VPN. Every v4 candidate is a
# deadlock; result is empty.
expect(
 "catchall-drops-all-v4",
 ips_only(wgrtc.filter_candidates_for_peer(
 cands("1.2.3.4", "10.0.0.1", "192.168.1.1"), "0.0.0.0/0")),
 [],
)

# /24 boundary: in-range IP dropped, out-of-range IP kept.
expect(
 "slash-24-drops-in-range-keeps-out",
 ips_only(wgrtc.filter_candidates_for_peer(
 cands("10.0.0.5", "10.0.1.5", "192.168.1.1"), "10.0.0.0/24")),
 ["10.0.1.5", "192.168.1.1"],
)

# Multiple AllowedIPs — union semantics; both ranges drop matching
# candidates.
expect(
 "multiple-ranges",
 ips_only(wgrtc.filter_candidates_for_peer(
 cands("10.0.0.1", "192.168.42.1", "203.0.113.5"),
 "10.0.0.0/24, 192.168.0.0/16")),
 ["203.0.113.5"],
)

# Whitespace + comma tolerance — wg show formats vary across kernel
# versions / wg-quick versus wg(8) directly.
expect(
 "whitespace-tolerance",
 ips_only(wgrtc.filter_candidates_for_peer(
 cands("10.0.0.5", "1.2.3.4"), " 10.0.0.0/24 , , ")),
 ["1.2.3.4"],
)

# Bare IP without prefix in AllowedIPs (treated as /32 host route).
expect(
 "bare-host-route-as-32",
 ips_only(wgrtc.filter_candidates_for_peer(
 cands("1.2.3.4", "1.2.3.5"), "1.2.3.4/32")),
 ["1.2.3.5"],
)

# Order of survivors preserved.
expect(
 "order-preserved",
 ips_only(wgrtc.filter_candidates_for_peer(
 cands("203.0.113.5", "10.0.0.1", "198.51.100.5", "192.168.1.1"),
 "10.0.0.0/24, 192.168.0.0/16")),
 ["203.0.113.5", "198.51.100.5"],
)

# Malformed AllowedIPs entry skipped silently — it'd be tragic if a
# typo in one peers.d entry disabled the filter for everything.
expect(
 "malformed-entry-skipped",
 ips_only(wgrtc.filter_candidates_for_peer(
 cands("10.0.0.5", "1.2.3.4"), "garbage, 10.0.0.0/24")),
 ["1.2.3.4"],
)

# v6 and v4 don't cross-pollute.
expect(
 "v4-not-affected-by-v6-allowed",
 ips_only(wgrtc.filter_candidates_for_peer(
 cands("1.2.3.4"), "::/0")),
 ["1.2.3.4"],
)

# Wide net (/8) with deep nesting.
expect(
 "slash-8-wide-net",
 ips_only(wgrtc.filter_candidates_for_peer(
 cands("10.99.5.1", "11.0.0.1"), "10.0.0.0/8")),
 ["11.0.0.1"],
)


# ─── GlobalConfig: AdvertiseInterfaces / SuppressInterfaces ──────

print()
print("=== GlobalConfig: Advertise/SuppressInterfaces (Step B conf knobs) ===")

def write_conf(body):
 f = tempfile.NamedTemporaryFile(
 mode="w", suffix=".conf", delete=False)
 f.write(body)
 f.flush()
 f.close()
 return f.name


def cfg(extra=""):
 body = f"""\
[Global]
Salt = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
PeerJsServer = wss://example.com/peerjs
PeerJsKey = test
{extra}

[Stun]
Servers = stun.example.com:3478
"""
 return wgrtc.load_global_config(write_conf(body))


# Default: empty lists when neither knob is set.
g = cfg()
expect("default-advertise-empty", g.advertise_interfaces, [])
expect("default-suppress-empty", g.suppress_interfaces, [])

# Single-entry CSV.
g = cfg("AdvertiseInterfaces = wg-mesh0\nSuppressInterfaces = docker0")
expect("advertise-single", g.advertise_interfaces, ["wg-mesh0"])
expect("suppress-single", g.suppress_interfaces, ["docker0"])

# Multi-entry CSV with whitespace.
g = cfg("AdvertiseInterfaces = eth0, wg-mesh0 , wlan0\n"
 "SuppressInterfaces = docker0, vmnet1")
expect("advertise-multi",
 g.advertise_interfaces,
 ["eth0", "wg-mesh0", "wlan0"])
expect("suppress-multi",
 g.suppress_interfaces,
 ["docker0", "vmnet1"])

# Empty entries (`,,`) skipped.
g = cfg("AdvertiseInterfaces = eth0,,wlan0,")
expect("advertise-empty-entries-skipped",
 g.advertise_interfaces,
 ["eth0", "wlan0"])


print()
print(f"summary: {pass_n} passed, {fail_n} failed")
sys.exit(0 if fail_n == 0 else 1)
