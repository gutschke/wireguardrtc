#!/usr/bin/env python3
# 43_sas_wire_format.py — daemon-side SAS wire format port.
#
# Mirrors signalling/SasWireFormat.kt + the test surface that
# SasWireFormatTest.kt covers on the Android side:
#  - routing-id derivation: BLAKE2b(code, key=label) base64url-no-pad,
#    with explicit initiator/responder domain separation.
#  - JSON envelopes: SAS_STEP_1 / SAS_STEP_2 / SAS_CONFIRM wrapped in
#    the OFFER shape that the public PeerJS broker accepts.
#  - SAS_CONFIRM MAC: keyed BLAKE2b-32 of role-specific label,
#    truncated to 16 bytes, with constant-time compare on verify.

import importlib.machinery
import importlib.util
import hashlib
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
loader = importlib.machinery.SourceFileLoader(
    "wgrtc", os.path.join(REPO, "wireguardrtc"))
spec = importlib.util.spec_from_loader("wgrtc", loader)
wgrtc = importlib.util.module_from_spec(spec)
loader.exec_module(wgrtc)


# ─── Routing-id derivation ──────────────────────────────────────────

def test_routing_ids_differ_per_role():
    code = b"ABCDEF"
    a = wgrtc.sas_routing_id_initiator(code)
    b = wgrtc.sas_routing_id_responder(code)
    assert a != b


def test_routing_ids_are_base64url_no_pad():
    code = b"ABCDEF"
    a = wgrtc.sas_routing_id_initiator(code)
    # base64url no-pad — no '=' and no '+' or '/'
    assert "=" not in a
    assert "+" not in a
    assert "/" not in a
    # 32-byte digest → 43 base64url chars
    assert len(a) == 43


def test_routing_id_matches_keyed_blake2b():
    code = b"ABCDEF"
    expected = hashlib.blake2b(code, digest_size=32,
                               key=wgrtc.SAS_LABEL_ROUTING_INIT).digest()
    # base64url-no-pad of that digest
    import base64
    expected_str = base64.urlsafe_b64encode(expected).rstrip(b"=").decode()
    assert wgrtc.sas_routing_id_initiator(code) == expected_str


def test_routing_id_deterministic():
    code = b"ABCDEF"
    assert wgrtc.sas_routing_id_initiator(code) == \
        wgrtc.sas_routing_id_initiator(code)


# ─── Step-1 / Step-2 envelope round-trip ───────────────────────────

def test_step1_envelope_round_trip():
    pake_msg = bytes(range(32))
    env = wgrtc.build_sas_step1_envelope("dst-routing", pake_msg)
    # Add the broker-side `src` field that a real message would carry.
    env["src"] = "alice-src"
    extracted = wgrtc.extract_sas_step1(env)
    assert extracted is not None
    src, msg = extracted
    assert src == "alice-src"
    assert msg == pake_msg


def test_step2_envelope_round_trip():
    pake_msg = bytes(reversed(range(32)))
    env = wgrtc.build_sas_step2_envelope("dst-routing", pake_msg)
    env["src"] = "bob-src"
    extracted = wgrtc.extract_sas_step2(env)
    assert extracted is not None
    src, msg = extracted
    assert src == "bob-src"
    assert msg == pake_msg


def test_step1_envelope_has_required_offer_shape():
    pake_msg = bytes(32)
    env = wgrtc.build_sas_step1_envelope("dst-routing", pake_msg)
    assert env["type"] == "OFFER"
    assert env["dst"] == "dst-routing"
    pl = env["payload"]
    assert pl["type"] == "data"
    assert "connectionId" in pl
    assert pl["connectionId"].startswith("dc_")
    assert pl["metadata"]["kind"] == "sas_step_1"
    assert pl["metadata"]["v"] == wgrtc.PROTOCOL_VERSION
    assert "pake_msg" in pl["metadata"]


def test_step_envelopes_reject_wrong_message_size():
    try:
        wgrtc.build_sas_step1_envelope("dst", b"\x00" * 16)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_extract_step1_rejects_step2_envelope():
    env = wgrtc.build_sas_step2_envelope("dst", bytes(32))
    env["src"] = "x"
    assert wgrtc.extract_sas_step1(env) is None


def test_extract_step_rejects_non_offer():
    env = {"type": "HEARTBEAT"}
    assert wgrtc.extract_sas_step1(env) is None


def test_extract_step_rejects_missing_src():
    env = wgrtc.build_sas_step1_envelope("dst", bytes(32))
    # No "src" added — should reject.
    assert wgrtc.extract_sas_step1(env) is None


def test_extract_step_rejects_wrong_version():
    env = wgrtc.build_sas_step1_envelope("dst", bytes(32))
    env["src"] = "x"
    env["payload"]["metadata"]["v"] = 999
    assert wgrtc.extract_sas_step1(env) is None


def test_extract_step_rejects_bad_pake_size():
    env = wgrtc.build_sas_step1_envelope("dst", bytes(32))
    env["src"] = "x"
    # Replace pake_msg with a shorter base64 blob.
    import base64
    env["payload"]["metadata"]["pake_msg"] = \
        base64.b64encode(b"too short").decode()
    assert wgrtc.extract_sas_step1(env) is None


# ─── Confirm envelope round-trip ─────────────────────────────────

def test_confirm_envelope_round_trip_no_info():
    mac = bytes(16)
    env = wgrtc.build_sas_confirm_envelope("dst", mac)
    env["src"] = "alice"
    extracted = wgrtc.extract_sas_confirm(env)
    assert extracted is not None
    src, got_mac, got_info = extracted
    assert src == "alice"
    assert got_mac == mac
    assert got_info is None


def test_confirm_envelope_round_trip_with_info():
    mac = bytes(16)
    info = b"some encrypted info blob bytes"
    env = wgrtc.build_sas_confirm_envelope("dst", mac, encrypted_info=info)
    env["src"] = "alice"
    extracted = wgrtc.extract_sas_confirm(env)
    assert extracted is not None
    src, got_mac, got_info = extracted
    assert got_mac == mac
    assert got_info == info


def test_confirm_rejects_wrong_mac_size():
    try:
        wgrtc.build_sas_confirm_envelope("dst", b"\x00" * 8)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_extract_confirm_rejects_bad_mac_size():
    env = wgrtc.build_sas_confirm_envelope("dst", bytes(16))
    env["src"] = "x"
    import base64
    env["payload"]["metadata"]["mac"] = base64.b64encode(b"\x00" * 8).decode()
    assert wgrtc.extract_sas_confirm(env) is None


# ─── Confirm MAC: keyed BLAKE2b truncated to 16 bytes ─────────────

def test_confirm_mac_initiator_matches_blake2b():
    sas_key = bytes(range(32))
    mac = wgrtc.build_sas_confirm_mac("initiator", sas_key)
    expected = hashlib.blake2b(wgrtc.SAS_LABEL_CONFIRM_INIT,
                               digest_size=32,
                               key=sas_key[:32]).digest()[:16]
    assert mac == expected


def test_confirm_mac_responder_matches_blake2b():
    sas_key = bytes(range(32))
    mac = wgrtc.build_sas_confirm_mac("responder", sas_key)
    expected = hashlib.blake2b(wgrtc.SAS_LABEL_CONFIRM_RESP,
                               digest_size=32,
                               key=sas_key[:32]).digest()[:16]
    assert mac == expected


def test_confirm_mac_initiator_differs_from_responder():
    sas_key = bytes(range(32))
    a = wgrtc.build_sas_confirm_mac("initiator", sas_key)
    b = wgrtc.build_sas_confirm_mac("responder", sas_key)
    assert a != b


def test_confirm_mac_verify_round_trip():
    sas_key = bytes(range(32))
    init_mac = wgrtc.build_sas_confirm_mac("initiator", sas_key)
    # Responder receives initiator's mac and verifies against init role.
    assert wgrtc.verify_sas_confirm_mac("initiator", sas_key, init_mac)


def test_confirm_mac_verify_rejects_wrong_role():
    sas_key = bytes(range(32))
    init_mac = wgrtc.build_sas_confirm_mac("initiator", sas_key)
    assert not wgrtc.verify_sas_confirm_mac("responder", sas_key, init_mac)


def test_confirm_mac_verify_rejects_wrong_key():
    sas_key_a = bytes(range(32))
    sas_key_b = bytes(reversed(range(32)))
    mac = wgrtc.build_sas_confirm_mac("initiator", sas_key_a)
    assert not wgrtc.verify_sas_confirm_mac("initiator", sas_key_b, mac)


def test_confirm_mac_verify_rejects_short_mac():
    sas_key = bytes(range(32))
    assert not wgrtc.verify_sas_confirm_mac("initiator", sas_key, b"\x00" * 8)


# ─── Driver ──────────────────────────────────────────────────────

def main():
    tests = [
        test_routing_ids_differ_per_role,
        test_routing_ids_are_base64url_no_pad,
        test_routing_id_matches_keyed_blake2b,
        test_routing_id_deterministic,
        test_step1_envelope_round_trip,
        test_step2_envelope_round_trip,
        test_step1_envelope_has_required_offer_shape,
        test_step_envelopes_reject_wrong_message_size,
        test_extract_step1_rejects_step2_envelope,
        test_extract_step_rejects_non_offer,
        test_extract_step_rejects_missing_src,
        test_extract_step_rejects_wrong_version,
        test_extract_step_rejects_bad_pake_size,
        test_confirm_envelope_round_trip_no_info,
        test_confirm_envelope_round_trip_with_info,
        test_confirm_rejects_wrong_mac_size,
        test_extract_confirm_rejects_bad_mac_size,
        test_confirm_mac_initiator_matches_blake2b,
        test_confirm_mac_responder_matches_blake2b,
        test_confirm_mac_initiator_differs_from_responder,
        test_confirm_mac_verify_round_trip,
        test_confirm_mac_verify_rejects_wrong_role,
        test_confirm_mac_verify_rejects_wrong_key,
        test_confirm_mac_verify_rejects_short_mac,
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
