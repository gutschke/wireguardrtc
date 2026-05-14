#!/usr/bin/env python3
# 52_stun_query_v6.py — V6.D1: production stun_query() must support
# both IPv4 and IPv6 STUN, not just IPv4.
#
# Acceptance criteria:
#   1. stun_query() takes a `family` kwarg (default IPv4 for back-
#      compat with all existing call sites).
#   2. With family=AF_INET6 and a v6-reachable STUN server, returns
#      a (v6_addr, port) tuple.
#   3. A new helper (get_public_ips_all) returns BOTH v4 + v6
#      reflexive addresses in one call so candidate enumeration can
#      iterate without keeping two parallel code paths.
#
# Tests are skipped on hosts that have no IPv6 connectivity at all
# (no AAAA route to the public internet) — they assert v4 keeps
# working but skip the v6 leg.  CI hosts without v6 still produce a
# green run.

import asyncio
import importlib.machinery
import importlib.util
import os
import socket
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
loader = importlib.machinery.SourceFileLoader(
    "wgrtc", os.path.join(REPO, "wireguardrtc"))
spec = importlib.util.spec_from_loader("wgrtc", loader)
wgrtc = importlib.util.module_from_spec(spec)
loader.exec_module(wgrtc)


STUN_V4 = "stun.l.google.com:19302"
STUN_V6 = "stun.l.google.com:19302"   # same host; dual-stack server


def _has_ipv6_egress() -> bool:
    """Best-effort detect: try opening a v6 UDP socket and binding to
    ::, then issuing a connect() to a known public v6 address.  No
    packet sent.  Returns True if the kernel finds a v6 route."""
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            s.bind(("::", 0))
            # 2001:4860:4860::8888 is Google DNS, always-reachable
            # canary for IPv6 internet.  connect() doesn't send any
            # packets for UDP; just sets the kernel route lookup.
            s.connect(("2001:4860:4860::8888", 53))
            return True
        finally:
            s.close()
    except OSError:
        return False


HAS_V6 = _has_ipv6_egress()


def _run(coro):
    """Helper to run an async coroutine from a sync test method."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class StunQueryV6Test(unittest.TestCase):

    def test_stun_query_family_kwarg_exists(self):
        """The function must accept a family kwarg without raising."""
        import inspect
        sig = inspect.signature(wgrtc.stun_query)
        self.assertIn("family", sig.parameters,
                      f"stun_query missing 'family' kwarg; got {list(sig.parameters)}")

    def test_stun_query_v4_default_still_works(self):
        """Back-compat: callers that pass no family flag must get
        the same IPv4 behaviour they always did."""
        res = _run(wgrtc.stun_query(STUN_V4))
        self.assertIsNotNone(res, "v4 STUN should return a result")
        ip, port = res
        self.assertIsInstance(ip, str)
        # Must be a v4 dotted-quad
        socket.inet_pton(socket.AF_INET, ip)
        self.assertTrue(0 < port < 65536)

    @unittest.skipUnless(HAS_V6, "host has no IPv6 egress")
    def test_stun_query_v6_returns_v6_address(self):
        """With family=AF_INET6 against a dual-stack STUN server,
        we should get a v6 reflexive address back."""
        res = _run(
            wgrtc.stun_query(STUN_V6, family=socket.AF_INET6))
        self.assertIsNotNone(res, "v6 STUN should return a result")
        ip, port = res
        socket.inet_pton(socket.AF_INET6, ip)
        self.assertTrue(0 < port < 65536)
        # Sanity: must not be a v4-mapped v6 address
        # (::ffff:a.b.c.d).  STUN over v6 should give a real v6.
        self.assertFalse(
            ip.startswith("::ffff:"),
            f"got v4-mapped address {ip}; STUN-over-v6 should "
            "return native v6 (no 4-in-6 mapping)"
        )


class GetPublicIpsAllTest(unittest.TestCase):
    """The dual-stack candidate enumerator.  Combines v4 + v6 from
    the same STUN-server list (servers that resolve to both A and
    AAAA get queried over both transports)."""

    def test_get_public_ips_all_exists(self):
        self.assertTrue(
            hasattr(wgrtc, "get_public_ips_all"),
            "expected a new get_public_ips_all helper"
        )

    def test_get_public_ips_all_returns_v4(self):
        class FakeState:
            public_ip = None
            stun_strict = False
        out = _run(
            wgrtc.get_public_ips_all([STUN_V4], FakeState()))
        # Returned list of (family, ip) tuples or similar — assert
        # at least one v4 entry came back.
        v4s = [entry for entry in out
               if (isinstance(entry, tuple) and entry[0] == socket.AF_INET)
               or (isinstance(entry, dict) and entry.get("family") == socket.AF_INET)]
        # Looser: at least one returned ip looks v4.
        ips = []
        for entry in out:
            if isinstance(entry, tuple) and len(entry) >= 2:
                ips.append(entry[1] if isinstance(entry[0], int) else entry[0])
            elif isinstance(entry, dict):
                ips.append(entry.get("ip", ""))
            else:
                ips.append(str(entry))
        v4_present = any(
            ":" not in ip and "." in ip for ip in ips
        )
        self.assertTrue(
            v4_present,
            f"expected at least one v4 address in {out}"
        )

    @unittest.skipUnless(HAS_V6, "host has no IPv6 egress")
    def test_get_public_ips_all_returns_both_families(self):
        class FakeState:
            public_ip = None
            stun_strict = False
        out = _run(
            wgrtc.get_public_ips_all([STUN_V4], FakeState()))
        ips = []
        for entry in out:
            if isinstance(entry, tuple) and len(entry) >= 2:
                # Could be (family, ip) or (ip, port); accept either.
                ips.append(entry[1] if isinstance(entry[0], int) else entry[0])
            elif isinstance(entry, dict):
                ips.append(entry.get("ip", ""))
            else:
                ips.append(str(entry))
        has_v4 = any(":" not in ip and "." in ip for ip in ips)
        has_v6 = any(":" in ip for ip in ips)
        self.assertTrue(has_v4 and has_v6,
                        f"expected both v4 and v6 in {out}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
