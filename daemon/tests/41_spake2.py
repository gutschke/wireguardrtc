#!/usr/bin/env python3
# 41_spake2.py — daemon-side SPAKE2 port.
#
# Targets parity with the Android signalling/Spake2.kt + Spake2Constants.kt
# implementation.  Tests mirror Android's Spake2Test.kt:
#  - round trip: same password → same key, complementary roles required.
#  - fresh randomness per session.
#  - identity binding: different ids → different keys.
#  - wrong password: divergent keys.
#  - rejection of malformed peer messages.
# Plus M/N derivation: both sides MUST produce identical Ristretto255
# constants from the labelled BLAKE2b digest.

import hashlib
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


# ─── M / N derived constants ─────────────────────────────────────────
# These bytes are derived deterministically from the Android labels
# (Spake2Constants.kt's M_LABEL / N_LABEL).  Both implementations
# compute them by BLAKE2b(label, key=null, 64 bytes) → ristretto255
# from_hash, so they MUST agree byte-for-byte to interop.

EXPECTED_M = "5867ff06e93104f66212871d013506c36c4eec473b76844ceee66b67ded78048"
EXPECTED_N = "fa5b91404aaafad6c485e6f33d00ab604dd588f73b828cc03a89db75265d0b19"


def test_M_constant_matches_android():
    assert wgrtc.SPAKE2_M.hex() == EXPECTED_M, \
        f"M divergence: {wgrtc.SPAKE2_M.hex()} vs {EXPECTED_M}"


def test_N_constant_matches_android():
    assert wgrtc.SPAKE2_N.hex() == EXPECTED_N, \
        f"N divergence: {wgrtc.SPAKE2_N.hex()} vs {EXPECTED_N}"


def test_M_and_N_are_valid_points():
    assert wgrtc.r255_is_valid_point(wgrtc.SPAKE2_M)
    assert wgrtc.r255_is_valid_point(wgrtc.SPAKE2_N)
    assert wgrtc.SPAKE2_M != wgrtc.SPAKE2_N


# ─── round-trip ──────────────────────────────────────────────────────

def test_roundtrip_same_password_yields_same_key():
    pwd = b"WORMHOLE"
    alice = wgrtc.Spake2(role="alice", password=pwd)
    bob = wgrtc.Spake2(role="bob", password=pwd)
    a_msg = alice.start()
    b_msg = bob.start()
    a_key = alice.finish(b_msg)
    b_key = bob.finish(a_msg)
    assert a_key == b_key, \
        f"keys differ:\n  alice: {a_key.hex()}\n  bob:   {b_key.hex()}"
    assert len(a_key) == 32


def test_fresh_randomness_per_session():
    pwd = b"WORMHOLE"
    a1 = wgrtc.Spake2(role="alice", password=pwd)
    b1 = wgrtc.Spake2(role="bob", password=pwd)
    a1_msg = a1.start()
    b1_msg = b1.start()
    k1 = a1.finish(b1_msg)
    b1.finish(a1_msg)

    a2 = wgrtc.Spake2(role="alice", password=pwd)
    b2 = wgrtc.Spake2(role="bob", password=pwd)
    a2_msg = a2.start()
    b2_msg = b2.start()
    k2 = a2.finish(b2_msg)
    b2.finish(a2_msg)
    assert k1 != k2, "fresh sessions should produce different keys"


def test_id_binding_changes_key():
    pwd = b"WORMHOLE"
    a1 = wgrtc.Spake2(role="alice", password=pwd,
                      id_a=b"alice@host1", id_b=b"bob@host2")
    b1 = wgrtc.Spake2(role="bob", password=pwd,
                      id_a=b"alice@host1", id_b=b"bob@host2")
    a1_msg = a1.start()
    b1_msg = b1.start()
    k_with_ids = a1.finish(b1_msg)
    assert k_with_ids == b1.finish(a1_msg)

    a2 = wgrtc.Spake2(role="alice", password=pwd,
                      id_a=b"alice@host1", id_b=b"DIFFERENT")
    b2 = wgrtc.Spake2(role="bob", password=pwd,
                      id_a=b"alice@host1", id_b=b"DIFFERENT")
    a2_msg = a2.start()
    b2_msg = b2.start()
    k_other_ids = a2.finish(b2_msg)
    assert k_other_ids != k_with_ids


def test_wrong_password_diverges():
    a = wgrtc.Spake2(role="alice", password=b"correct")
    b = wgrtc.Spake2(role="bob", password=b"WRONG")
    a_msg = a.start()
    b_msg = b.start()
    a_key = a.finish(b_msg)
    b_key = b.finish(a_msg)
    assert a_key != b_key


def test_role_mismatch_both_alice():
    pwd = b"WORMHOLE"
    a1 = wgrtc.Spake2(role="alice", password=pwd)
    a2 = wgrtc.Spake2(role="alice", password=pwd)
    a1_msg = a1.start()
    a2_msg = a2.start()
    k1 = a1.finish(a2_msg)
    k2 = a2.finish(a1_msg)
    # Both-alice yields different keys — same role processes the
    # same M-blinding on both sides; the algebra doesn't line up.
    assert k1 != k2


# ─── validation ─────────────────────────────────────────────────────

def test_peer_message_must_be_32_bytes():
    a = wgrtc.Spake2(role="alice", password=b"x")
    a.start()
    try:
        a.finish(b"\x00" * 31)
        raise AssertionError("expected ValueError on 31-byte peer message")
    except ValueError:
        pass


def test_invalid_peer_point_rejected():
    a = wgrtc.Spake2(role="alice", password=b"x")
    a.start()
    bad = bytes.fromhex(
        "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
    try:
        a.finish(bad)
        raise AssertionError("expected ValueError on invalid point")
    except ValueError:
        pass


def test_start_must_be_before_finish():
    a = wgrtc.Spake2(role="alice", password=b"x")
    try:
        a.finish(b"\x00" * 32)
        raise AssertionError("expected RuntimeError when finish before start")
    except (RuntimeError, ValueError):
        pass


def test_start_only_once():
    a = wgrtc.Spake2(role="alice", password=b"x")
    a.start()
    try:
        a.start()
        raise AssertionError("expected RuntimeError on second start()")
    except RuntimeError:
        pass


def test_start_produces_valid_point():
    msg = wgrtc.Spake2(role="alice", password=b"x").start()
    assert len(msg) == 32
    assert wgrtc.r255_is_valid_point(msg)


# ─── deterministic interop fixture ─────────────────────────────────
# When both sides use identical priv scalars + identical password,
# the resulting session keys are deterministic.  This is the
# "wire-format" test: if Android computes the same byte string for the
# same inputs, the protocols are byte-compatible.  We don't have an
# Android-generated fixture for the key, so we just self-check the
# determinism here and rely on the underlying primitives (matched
# against libsodium in 40_ristretto255) for cross-impl byte equality.

def test_deterministic_with_fixed_scalars():
    pwd = b"WORMHOLE"
    a_priv = (12345).to_bytes(32, 'little')
    b_priv = (67890).to_bytes(32, 'little')
    a1 = wgrtc.Spake2(role="alice", password=pwd, _test_priv_scalar=a_priv)
    b1 = wgrtc.Spake2(role="bob", password=pwd, _test_priv_scalar=b_priv)
    a1_msg = a1.start()
    b1_msg = b1.start()
    k1 = a1.finish(b1_msg)
    b1.finish(a1_msg)

    # Recompute with identical seeds → identical key.
    a2 = wgrtc.Spake2(role="alice", password=pwd, _test_priv_scalar=a_priv)
    b2 = wgrtc.Spake2(role="bob", password=pwd, _test_priv_scalar=b_priv)
    a2_msg = a2.start()
    b2_msg = b2.start()
    k2 = a2.finish(b2_msg)
    b2.finish(a2_msg)

    assert k1 == k2, f"determinism broken: {k1.hex()} vs {k2.hex()}"


# ─── Driver ─────────────────────────────────────────────────────────

def main():
    tests = [
        test_M_constant_matches_android,
        test_N_constant_matches_android,
        test_M_and_N_are_valid_points,
        test_roundtrip_same_password_yields_same_key,
        test_fresh_randomness_per_session,
        test_id_binding_changes_key,
        test_wrong_password_diverges,
        test_role_mismatch_both_alice,
        test_peer_message_must_be_32_bytes,
        test_invalid_peer_point_rejected,
        test_start_must_be_before_finish,
        test_start_only_once,
        test_start_produces_valid_point,
        test_deterministic_with_fixed_scalars,
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
