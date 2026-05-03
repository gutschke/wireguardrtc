#!/usr/bin/env python3
# 19_stun_strict.py — verify [Stun] Strict = yes rejects STUN responses
# with non-globally-routable addresses, and that the loose default
# accepts them.
#
# Drives get_public_ipv4() with monkey-patched stun_query() and a stub
# state object so we don't need any real STUN server / network.

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


# A scripted stub that returns whatever the test queues up.
QUEUE: list = []
async def stub_stun_query(server, timeout=2.5):
    return QUEUE.pop(0) if QUEUE else None


wgrtc.stun_query = stub_stun_query


def state(strict: bool):
    return types.SimpleNamespace(public_ip=None, stun_strict=strict)


pass_n = 0
fail_n = 0
def expect(desc, actual, want):
    global pass_n, fail_n
    if actual == want:
        print(f"  PASS [{desc}] -> {actual}")
        pass_n += 1
    else:
        print(f"  FAIL [{desc}] expected {want!r} got {actual!r}")
        fail_n += 1


def run(strict, queue, servers=("a", "b", "c")):
    global QUEUE
    QUEUE = list(queue)
    return asyncio.run(wgrtc.get_public_ipv4(list(servers), state(strict)))


print("=== loose mode (Strict=no, default) ===")
expect("global-public",  run(False, [("1.1.1.1", 0)]),  "1.1.1.1")
# Loose mode accepts private/CGN/etc.  Documented as "LAN-aware" default.
expect("private-lan",    run(False, [("192.168.1.5", 0)]),  "192.168.1.5")
expect("cgn-100.64",     run(False, [("100.64.0.5", 0)]),   "100.64.0.5")

print()
print("=== strict mode (Strict=yes) ===")
# A first-hop hijacked STUN feeds us a private address; strict skips it.
expect("private-rejected-falls-through-to-public",
       run(True, [("10.0.0.5", 0), ("1.1.1.1", 0)]),
       "1.1.1.1")
expect("cgn-rejected-falls-through",
       run(True, [("100.64.5.5", 0), ("8.8.8.8", 0)]),
       "8.8.8.8")
expect("loopback-rejected",
       run(True, [("127.0.0.1", 0), ("1.1.1.1", 0)]),
       "1.1.1.1")
expect("global-accepted",
       run(True, [("1.1.1.1", 0)]),
       "1.1.1.1")
# All servers report private → no public IP available, fail closed.
expect("all-private-fails",
       run(True, [("10.0.0.1", 0), ("192.168.1.1", 0), ("172.16.0.1", 0)]),
       None)
# Malformed ext_ip handled gracefully.
expect("garbage-ip-rejected",
       run(True, [("not-an-ip", 0), ("1.1.1.1", 0)]),
       "1.1.1.1")

print()
print(f"summary: {pass_n} passed, {fail_n} failed")
sys.exit(0 if fail_n == 0 else 1)
