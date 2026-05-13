#!/usr/bin/env python3
# 31_classify_nat.py — unit tests for the NAT-type classifier.
#
# The classifier takes a list of (server, src_port, ext_ip, ext_port)
# probe results and returns a structured verdict.  Lives in the daemon
# so both the CLI flag (--check-nat) and the legacy
# tests/01_stun_nat.py probe-and-print path share the same logic.
#
# Pure-data tests — no STUN, no sockets.

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


def assert_eq(actual, expected, msg=""):
    if actual != expected:
        raise AssertionError(f"{msg}: expected {expected!r}, got {actual!r}")


def assert_true(cond, msg=""):
    if not cond:
        raise AssertionError(f"{msg}: condition was false")


# ─── No data ────────────────────────────────────────────────────────────

def test_no_data():
    v = wgrtc.classify_nat_result([])
    assert_eq(v.kind, "no_data", "kind on empty probes")
    assert_eq(v.wgrtc_viable, False, "no probes → not viable")
    assert_eq(v.external_ips, [], "no IPs observed")
    # Summary should mention "no" or "fail" — case-insensitive.
    assert_true("no " in v.summary.lower() or "fail" in v.summary.lower(),
                f"summary should reference no data: {v.summary!r}")


# ─── Single probe — insufficient to decide cone vs symmetric ────────────

def test_single_probe_insufficient():
    # One server + one src port + port preserved.  We can see the
    # external mapping but can't tell whether a SECOND destination
    # would get the same external port (cone test needs ≥ 2 dests).
    probes = [("stun.example.org", 51000, "203.0.113.5", 51000)]
    v = wgrtc.classify_nat_result(probes)
    # The classifier should be honest: it can confirm port-preservation
    # for this src, but cone-vs-symmetric is unknown.
    assert_eq(v.port_preserving, True, "single probe, ext == src → preserving")
    assert_eq(v.cone, None, "single probe insufficient to decide cone")
    assert_eq(v.external_ips, ["203.0.113.5"], "one external IP")


# ─── Two probes from same src to two servers — cone test possible ──────

def test_cone_and_port_preserving():
    probes = [
        ("stun.a", 51000, "203.0.113.5", 51000),
        ("stun.b", 51000, "203.0.113.5", 51000),
        ("stun.c", 51000, "203.0.113.5", 51000),
    ]
    v = wgrtc.classify_nat_result(probes)
    assert_eq(v.kind, "no_nat_or_cone_port_preserving", "best case kind")
    assert_eq(v.cone, True, "same ext port across servers → cone")
    assert_eq(v.port_preserving, True, "ext == src → preserving")
    assert_eq(v.wgrtc_viable, True, "best case is viable")


def test_cone_not_port_preserving():
    # Same ext port across all servers (so cone), but it's been
    # remapped to a different number than the local source.
    probes = [
        ("stun.a", 51000, "203.0.113.5", 47123),
        ("stun.b", 51000, "203.0.113.5", 47123),
        ("stun.c", 51000, "203.0.113.5", 47123),
    ]
    v = wgrtc.classify_nat_result(probes)
    assert_eq(v.kind, "cone_not_port_preserving", "cone but ports remapped")
    assert_eq(v.cone, True, "ports stable across servers → cone")
    assert_eq(v.port_preserving, False, "ext != src → not preserving")
    assert_eq(v.wgrtc_viable, False,
              "non-preserving cone needs NAT-PMP/PCP to be viable")


def test_symmetric():
    # Same src port, DIFFERENT ext ports per server → symmetric.
    probes = [
        ("stun.a", 51000, "203.0.113.5", 47000),
        ("stun.b", 51000, "203.0.113.5", 47001),
        ("stun.c", 51000, "203.0.113.5", 47002),
    ]
    v = wgrtc.classify_nat_result(probes)
    assert_eq(v.kind, "symmetric", "different ext ports per server → symmetric")
    assert_eq(v.cone, False, "not cone")
    assert_eq(v.wgrtc_viable, False, "symmetric NAT is not viable for wgrtc")


# ─── Multiple external IPs (multi-WAN / weird STUN servers) ─────────────

def test_multiple_external_ips_listed():
    # Same src port, same ext port, but two different ext IPs reported.
    # Unusual; flag in summary but classifier should still produce a
    # best-effort verdict.
    probes = [
        ("stun.a", 51000, "203.0.113.5", 51000),
        ("stun.b", 51000, "198.51.100.7", 51000),
    ]
    v = wgrtc.classify_nat_result(probes)
    assert_eq(sorted(v.external_ips), ["198.51.100.7", "203.0.113.5"],
              "both ext IPs reported")
    # Note: classifier may or may not call this case viable; either
    # behaviour is defensible.  Just assert structure is consistent.
    assert_true(v.kind in ("no_nat_or_cone_port_preserving",
                            "cone_not_port_preserving",
                            "symmetric", "no_data"),
                f"kind must be a known value: {v.kind!r}")


# ─── Multiple src ports — classifier handles per-src grouping ───────────

def test_multiple_src_ports_independent():
    # Each src port is its own "test" — the classifier should
    # decide cone/symmetric based on whether ANY src has differing
    # ext ports across servers.
    probes = [
        # src 51000: cone (same ext port across servers)
        ("stun.a", 51000, "203.0.113.5", 51000),
        ("stun.b", 51000, "203.0.113.5", 51000),
        # src 52000: also cone
        ("stun.a", 52000, "203.0.113.5", 52000),
        ("stun.b", 52000, "203.0.113.5", 52000),
    ]
    v = wgrtc.classify_nat_result(probes)
    assert_eq(v.cone, True, "all srcs cone → cone")
    assert_eq(v.port_preserving, True, "all ext == src")


def test_one_src_symmetric_blocks_verdict():
    # Even if src 51000 looks cone, src 52000 being symmetric is enough
    # to call the whole thing symmetric — the bad behaviour will bite.
    probes = [
        ("stun.a", 51000, "203.0.113.5", 51000),
        ("stun.b", 51000, "203.0.113.5", 51000),
        ("stun.a", 52000, "203.0.113.5", 60000),
        ("stun.b", 52000, "203.0.113.5", 60001),
    ]
    v = wgrtc.classify_nat_result(probes)
    assert_eq(v.cone, False, "any src showing symmetric → not cone")
    assert_eq(v.wgrtc_viable, False, "mixed symmetric blocks viability")


# ─── Summary text is non-empty and informative ─────────────────────────

def test_summary_text_non_empty_for_all_kinds():
    for probes, expected_kind in [
        ([], "no_data"),
        ([("a", 51000, "203.0.113.5", 51000),
          ("b", 51000, "203.0.113.5", 51000)], "no_nat_or_cone_port_preserving"),
        ([("a", 51000, "203.0.113.5", 47000),
          ("b", 51000, "203.0.113.5", 47000)], "cone_not_port_preserving"),
        ([("a", 51000, "203.0.113.5", 47000),
          ("b", 51000, "203.0.113.5", 47001)], "symmetric"),
    ]:
        v = wgrtc.classify_nat_result(probes)
        assert_eq(v.kind, expected_kind, f"kind for {probes!r}")
        assert_true(len(v.summary) > 10,
                    f"summary should be non-trivial for {expected_kind}: "
                    f"{v.summary!r}")


# ─── Driver ─────────────────────────────────────────────────────────────

def main():
    tests = [
        test_no_data,
        test_single_probe_insufficient,
        test_cone_and_port_preserving,
        test_cone_not_port_preserving,
        test_symmetric,
        test_multiple_external_ips_listed,
        test_multiple_src_ports_independent,
        test_one_src_symmetric_blocks_verdict,
        test_summary_text_non_empty_for_all_kinds,
    ]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"  ✓ {t.__name__}")
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}")
            failures += 1
    print()
    print(f"{len(tests) - failures}/{len(tests)} passed")
    sys.exit(0 if failures == 0 else 1)


if __name__ == "__main__":
    main()
