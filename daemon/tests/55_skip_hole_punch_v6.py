#!/usr/bin/env python3
# 55_skip_hole_punch_v6.py — V6.D5: raw_inject() and wake_via_iface()
# are IPv4-only by construction (AF_INET raw socket; build_raw_udp_packet
# emits a v4 header).  When the active peer endpoint is v6, we must
# skip those calls — passing a v6 destination would either error or
# silently no-op.  IPv6 typically doesn't NAT, so the kernel WG
# module dials the endpoint directly without raw-inject help.
#
# This file tests the small classifier helper that gates the skip,
# plus that the daemon's main loop honours it.  The classifier is
# the unit-testable surface; integration coverage of "active v6
# peer → no raw-inject" is in a separate fabric test (deferred —
# the in-process daemon main loop is async + IO-heavy and pulls in
# WgrtcState, RawHelperClient, etc.).

import asyncio
import importlib.machinery
import importlib.util
import os
import sys

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


# ─── _endpoint_is_v6 classifier ───────────────────────────────────

expect("_endpoint_is_v6 helper exists",
       hasattr(wgrtc, "_endpoint_is_v6"),
       "")

if hasattr(wgrtc, "_endpoint_is_v6"):
    # Bare v6
    expect("bare GUA v6 is v6",
           wgrtc._endpoint_is_v6("2001:db8::1"),
           "")
    expect("bare ULA v6 is v6",
           wgrtc._endpoint_is_v6("fd00::1"),
           "")
    # Bare v4
    expect("bare v4 is not v6",
           not wgrtc._endpoint_is_v6("203.0.113.5"),
           "")
    # Garbage
    expect("garbage is not v6",
           not wgrtc._endpoint_is_v6("not-an-address"),
           "")
    expect("empty is not v6",
           not wgrtc._endpoint_is_v6(""),
           "")
    expect("None is not v6 (defensive)",
           not wgrtc._endpoint_is_v6(None),
           "")
    # The classifier should also tolerate trailing port (sometimes
    # we have "ip:port" or "[ip]:port" strings).
    expect("v6 with bracketed port is v6",
           wgrtc._endpoint_is_v6("[2001:db8::1]:51820"),
           "")
    expect("v4 with port is not v6",
           not wgrtc._endpoint_is_v6("203.0.113.5:51820"),
           "")


# ─── Behavioural check via raw_inject ─────────────────────────────
# The standalone raw_inject() function (not the daemon's
# RawHelperClient seam) should refuse a v6 destination rather than
# crashing inside socket.inet_aton().  Tests run as a non-root
# user so we expect PermissionError on the raw socket creation
# anyway — but the v6 reject must come BEFORE the socket call so
# unprivileged callers see a clean "wrong family" return value.

if hasattr(wgrtc, "raw_inject"):
    # Calling raw_inject() with a v6 destination should return
    # False (skipped) without raising — and without ever
    # attempting to open the raw socket.
    rv = wgrtc.raw_inject(51820, "2001:db8::1", 51820)
    expect("raw_inject returns False for v6 destination",
           rv is False,
           f"got {rv!r}")


# ─── RawHelperClient v6-skip wiring ───────────────────────────────
# Even via the privileged-broker RPC path the daemon must not send
# v6 destinations to the helper.  The helper itself is v4-only;
# sending it a v6 op wastes an IPC round-trip and produces a noisy
# "refused" log on the helper side.  Tests use a fake _rpc that
# RECORDS every call so we can assert the RPC was (or wasn't)
# attempted.

class FakeRawClient(wgrtc.RawHelperClient):
    def __init__(self):
        # Skip the parent __init__ that would try to connect to a
        # real socket.  We only override _rpc.
        self.calls = []
    async def _rpc(self, req):
        self.calls.append(req)
        return {"ok": True}

async def _exercise_raw_client():
    c = FakeRawClient()
    # v4 inject → RPC sent
    ok_v4 = await c.inject("wg0", 51820, "203.0.113.5", 51820)
    expect("v4 inject sends an RPC",
           ok_v4 and any(r["op"] == "inject" and r["dst_ip"] == "203.0.113.5"
                          for r in c.calls),
           f"calls={c.calls}")
    # v6 inject → NO RPC sent, returns False
    c.calls.clear()
    rv = await c.inject("wg0", 51820, "2001:db8::5", 51820)
    expect("v6 inject does NOT send an RPC",
           rv is False and c.calls == [],
           f"rv={rv} calls={c.calls}")
    # v4 wake → RPC sent
    ok = await c.wake("wg0", "10.99.0.1")
    expect("v4 wake sends an RPC",
           ok and any(r["op"] == "wake" and r["target_ip"] == "10.99.0.1"
                       for r in c.calls),
           f"calls={c.calls}")
    # v6 wake → NO RPC sent
    c.calls.clear()
    rv = await c.wake("wg0", "fd00::1")
    expect("v6 wake does NOT send an RPC",
           rv is False and c.calls == [],
           f"rv={rv} calls={c.calls}")

asyncio.run(_exercise_raw_client())


print()
print(f"summary: {pass_n} passed, {fail_n} failed")
sys.exit(0 if fail_n == 0 else 1)
