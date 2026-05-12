#!/usr/bin/env python3
# 25_parallel_stun.py — verifies the daemon's STUN code fires all
# configured servers in parallel.
#
# Two functions are exercised:
#
# get_public_ipv4(servers, state)
# Returns the FIRST valid response (under strict-mode filtering)
# across all servers fired in parallel. Caller-visible API matches
# the pre-Step-H behaviour for back-compat.
#
# get_public_ipv4_all(servers, state)
# Returns the deduped list of all valid responses, in completion
# order. Step C (multi-candidate enumeration on the sender side)
# uses this — a multi-homed daemon discovers every reflexive
# address its various interfaces map to without burning N sequential
# STUN_TIMEOUT windows when slow servers are mixed with fast ones.
#
# The test patches wgrtc.stun_query with a server-keyed stub and asserts
# correctness of dedup, strict filtering, and timing (parallel ≠
# sequential — total wall-clock is the slowest, not the sum).

import asyncio
import importlib.machinery
import importlib.util
import os
import sys
import time
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


def make_stub(responses, delays=None):
 """Build a stub stun_query that returns `responses[server]` after
 `delays.get(server, 0)` seconds. Lets us simulate slow servers
 and verify parallel firing."""
 delays = delays or {}
 async def stub(server, timeout=2.5):
 if server in delays:
 await asyncio.sleep(delays[server])
 return responses.get(server)
 return stub


def state(strict=False, public_ip=None):
 return types.SimpleNamespace(public_ip=public_ip, stun_strict=strict)


def run_first(servers, responses, delays=None, strict=False):
 wgrtc.stun_query = make_stub(responses, delays)
 return asyncio.run(wgrtc.get_public_ipv4(list(servers), state(strict)))


def run_all(servers, responses, delays=None, strict=False):
 wgrtc.stun_query = make_stub(responses, delays)
 return asyncio.run(wgrtc.get_public_ipv4_all(list(servers), state(strict)))


# ─── get_public_ipv4: single-result API ────────────────────────────

print("=== get_public_ipv4 (back-compat single-result API) ===")

# Single server, single answer → trivial.
expect(
 "single-server-happy",
 run_first(["a"], {"a": ("1.2.3.4", 0)}),
 "1.2.3.4",
)

# Three servers, all return the SAME IP (typical home router NAT).
# Returns it; no preference for which "first" since they're identical.
expect(
 "three-servers-same-ip",
 run_first(["a", "b", "c"],
 {"a": ("1.1.1.1", 0), "b": ("1.1.1.1", 0), "c": ("1.1.1.1", 0)}),
 "1.1.1.1",
)

# Mixed: one fast valid response, two slow. Parallel firing should
# return the fast one without waiting for the slow ones. Assert
# wall-clock < sum-of-delays.
def timed_first(servers, responses, delays=None, strict=False):
 t0 = time.monotonic()
 r = run_first(servers, responses, delays, strict)
 return r, time.monotonic() - t0


r, dt = timed_first(
 ["fast", "slow1", "slow2"],
 {"fast": ("1.1.1.1", 0), "slow1": ("2.2.2.2", 0), "slow2": ("3.3.3.3", 0)},
 {"slow1": 1.0, "slow2": 1.0},
)
expect("parallel-fast-wins", r, "1.1.1.1")
# Sum-of-delays is 2 s; parallel wall-clock should be ≪ 2 s. Allow
# generous slack (test boxes can be flaky) — anything under 0.5 s is
# clearly parallel.
expect("parallel-completes-fast (dt < 0.5s)",
 dt < 0.5,
 True)

# Strict mode under parallel: invalid responses are filtered, the
# first-completing valid one wins.
expect(
 "strict-private-rejected-first-public-wins",
 run_first(["a", "b"],
 {"a": ("10.0.0.5", 0), "b": ("1.1.1.1", 0)},
 strict=True),
 "1.1.1.1",
)

# All servers respond with private addresses → strict mode returns None.
expect(
 "strict-all-private-fails",
 run_first(["a", "b"],
 {"a": ("10.0.0.5", 0), "b": ("192.168.1.1", 0)},
 strict=True),
 None,
)

# All servers timed out (None responses) → returns None.
expect(
 "all-timeouts-fails",
 run_first(["a", "b", "c"], {"a": None, "b": None, "c": None}),
 None,
)

# PublicIp override bypasses STUN entirely.
wgrtc.stun_query = make_stub({}) # would error if called
expect(
 "public-ip-override-skips-stun",
 asyncio.run(wgrtc.get_public_ipv4(
 ["a", "b"], state(public_ip="9.9.9.9"))),
 "9.9.9.9",
)


# ─── get_public_ipv4_all: parallel multi-result API ────────────────

print()
print("=== get_public_ipv4_all (parallel multi-result API) ===")

# Multi-homed: two servers see different external IPs (different
# upstream paths). Both should appear in the result.
expect(
 "multi-homed-distinct-ips",
 sorted(run_all(["a", "b"],
 {"a": ("1.1.1.1", 0), "b": ("8.8.8.8", 0)})),
 ["1.1.1.1", "8.8.8.8"],
)

# Three servers, all see the same IP (single-homed). Result is
# deduped to a one-element list.
expect(
 "single-homed-deduped",
 run_all(["a", "b", "c"],
 {"a": ("1.1.1.1", 0), "b": ("1.1.1.1", 0), "c": ("1.1.1.1", 0)}),
 ["1.1.1.1"],
)

# Mixed: one server saw the same IP, one saw a different one,
# one timed out. Two distinct IPs in result.
expect(
 "mixed-dedup-and-timeout",
 sorted(run_all(["a", "b", "c"],
 {"a": ("1.1.1.1", 0), "b": ("1.1.1.1", 0),
 "c": ("8.8.8.8", 0)})),
 ["1.1.1.1", "8.8.8.8"],
)

# Strict mode filters: private addresses dropped from the list.
expect(
 "strict-filters-private",
 run_all(["a", "b"],
 {"a": ("10.0.0.5", 0), "b": ("1.1.1.1", 0)},
 strict=True),
 ["1.1.1.1"],
)

# Strict, all private → empty list (NOT None — caller distinguishes
# "STUN couldn't reach anyone" from "STUN reached but found nothing
# globally-routable").
expect(
 "strict-all-private-empty-list",
 run_all(["a", "b"],
 {"a": ("10.0.0.5", 0), "b": ("192.168.1.1", 0)},
 strict=True),
 [],
)

# All timed out → empty list.
expect(
 "all-timeouts-empty-list",
 run_all(["a", "b"], {"a": None, "b": None}),
 [],
)

# PublicIp override: returns a one-element list with the override,
# skips STUN.
wgrtc.stun_query = make_stub({})
expect(
 "public-ip-override-returns-single",
 asyncio.run(wgrtc.get_public_ipv4_all(
 ["a", "b"], state(public_ip="9.9.9.9"))),
 ["9.9.9.9"],
)


print()
print(f"summary: {pass_n} passed, {fail_n} failed")
sys.exit(0 if fail_n == 0 else 1)
