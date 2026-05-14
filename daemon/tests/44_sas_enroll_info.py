#!/usr/bin/env python3
# 44_sas_enroll_info.py — encrypted enrollment payload for sas_confirm.
#
# Mirrors SasEnrollInfo.kt: the optional `info` field of a SAS_CONFIRM
# carries a secretbox-encrypted JSON blob.  Joiner→host sends a
# JoinerEnrollInfo (wg pubkey + device name).  Host→joiner sends a
# HostEnrollInfo (wg pubkey, endpoint, assigned address, AllowedIPs,
# optional broker, DNS, MTU, keepalive, host name).
#
# Both carry version + timestamp.  Decoder rejects wrong version,
# stale timestamp, malformed JSON, bad wg_pubkey.  Silent failure —
# error shapes shouldn't be observable to a network attacker.

import base64
import importlib.machinery
import importlib.util
import os
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
loader = importlib.machinery.SourceFileLoader(
    "wgrtc", os.path.join(REPO, "wireguardrtc"))
spec = importlib.util.spec_from_loader("wgrtc", loader)
wgrtc = importlib.util.module_from_spec(spec)
loader.exec_module(wgrtc)


SAS_KEY = bytes(range(32))
WG_PUBKEY_B64 = base64.b64encode(bytes(32)).decode("ascii")


# ─── Joiner → Host ────────────────────────────────────────────────

def test_encode_decode_joiner_minimal():
    blob = wgrtc.encode_joiner_enroll_info(
        sas_key=SAS_KEY,
        wg_pubkey_b64=WG_PUBKEY_B64,
    )
    info = wgrtc.decode_joiner_enroll_info(blob, sas_key=SAS_KEY)
    assert info is not None
    assert info["wg_pubkey"] == WG_PUBKEY_B64
    assert info.get("device_name") is None
    assert info["v"] == wgrtc.PROTOCOL_VERSION


def test_encode_decode_joiner_with_device_name():
    blob = wgrtc.encode_joiner_enroll_info(
        sas_key=SAS_KEY,
        wg_pubkey_b64=WG_PUBKEY_B64,
        device_name="laptop-friend",
    )
    info = wgrtc.decode_joiner_enroll_info(blob, sas_key=SAS_KEY)
    assert info["device_name"] == "laptop-friend"


def test_decode_joiner_rejects_wrong_key():
    blob = wgrtc.encode_joiner_enroll_info(sas_key=SAS_KEY,
                                            wg_pubkey_b64=WG_PUBKEY_B64)
    wrong = bytes(reversed(range(32)))
    assert wgrtc.decode_joiner_enroll_info(blob, sas_key=wrong) is None


def test_decode_joiner_rejects_stale_timestamp():
    blob = wgrtc.encode_joiner_enroll_info(
        sas_key=SAS_KEY,
        wg_pubkey_b64=WG_PUBKEY_B64,
        timestamp=int(time.time()) - 10000,  # 2.8 hours ago
    )
    assert wgrtc.decode_joiner_enroll_info(blob, sas_key=SAS_KEY) is None


def test_decode_joiner_rejects_bad_pubkey():
    # Encoded pubkey isn't 32 bytes after base64-decode.
    bad_pubkey = base64.b64encode(b"too short").decode("ascii")
    blob = wgrtc.encode_joiner_enroll_info(
        sas_key=SAS_KEY, wg_pubkey_b64=bad_pubkey)
    assert wgrtc.decode_joiner_enroll_info(blob, sas_key=SAS_KEY) is None


def test_decode_joiner_rejects_short_key():
    blob = wgrtc.encode_joiner_enroll_info(
        sas_key=SAS_KEY, wg_pubkey_b64=WG_PUBKEY_B64)
    assert wgrtc.decode_joiner_enroll_info(blob, sas_key=b"short") is None


# ─── Host → Joiner ────────────────────────────────────────────────

def _full_host_info(sas_key=SAS_KEY):
    return wgrtc.encode_host_enroll_info(
        sas_key=sas_key,
        wg_pubkey_b64=WG_PUBKEY_B64,
        wg_endpoint="203.0.113.5:51820",
        assigned_address="10.99.0.2/32",
        allowed_ips="10.99.0.1/32",
        broker_wss="wss://0.peerjs.com/peerjs",
        broker_key="peerjs",
        salt_b64=base64.b64encode(bytes(16)).decode("ascii"),
        dns="1.1.1.1",
        mtu=1280,
        keepalive=25,
        host_name="my-server",
    )


def test_encode_decode_host_full():
    blob = _full_host_info()
    info = wgrtc.decode_host_enroll_info(blob, sas_key=SAS_KEY)
    assert info is not None
    assert info["wg_pubkey"] == WG_PUBKEY_B64
    assert info["wg_endpoint"] == "203.0.113.5:51820"
    assert info["assigned_address"] == "10.99.0.2/32"
    assert info["allowed_ips"] == "10.99.0.1/32"
    assert info["broker_wss"] == "wss://0.peerjs.com/peerjs"
    assert info["mtu"] == 1280
    assert info["keepalive"] == 25
    assert info["host_name"] == "my-server"


def test_encode_decode_host_minimal():
    blob = wgrtc.encode_host_enroll_info(
        sas_key=SAS_KEY,
        wg_pubkey_b64=WG_PUBKEY_B64,
        wg_endpoint="203.0.113.5:51820",
        assigned_address="10.99.0.2/32",
        allowed_ips="10.99.0.1/32",
    )
    info = wgrtc.decode_host_enroll_info(blob, sas_key=SAS_KEY)
    assert info is not None
    assert info.get("dns") is None
    assert info.get("mtu") is None
    assert info.get("keepalive") is None


def test_decode_host_rejects_wrong_key():
    blob = _full_host_info()
    wrong = bytes(reversed(range(32)))
    assert wgrtc.decode_host_enroll_info(blob, sas_key=wrong) is None


def test_decode_host_rejects_stale_timestamp():
    blob = wgrtc.encode_host_enroll_info(
        sas_key=SAS_KEY,
        wg_pubkey_b64=WG_PUBKEY_B64,
        wg_endpoint="x:1",
        assigned_address="10.0.0.2/32",
        allowed_ips="10.0.0.1/32",
        timestamp=int(time.time()) - 10000,
    )
    assert wgrtc.decode_host_enroll_info(blob, sas_key=SAS_KEY) is None


def test_decode_host_rejects_bad_pubkey():
    bad_pubkey = base64.b64encode(b"X" * 20).decode("ascii")
    blob = wgrtc.encode_host_enroll_info(
        sas_key=SAS_KEY,
        wg_pubkey_b64=bad_pubkey,
        wg_endpoint="x:1",
        assigned_address="10.0.0.2/32",
        allowed_ips="10.0.0.1/32",
    )
    assert wgrtc.decode_host_enroll_info(blob, sas_key=SAS_KEY) is None


def test_decode_host_rejects_garbage():
    assert wgrtc.decode_host_enroll_info(b"\x00" * 64, sas_key=SAS_KEY) is None


# ─── Driver ──────────────────────────────────────────────────────

def main():
    tests = [
        test_encode_decode_joiner_minimal,
        test_encode_decode_joiner_with_device_name,
        test_decode_joiner_rejects_wrong_key,
        test_decode_joiner_rejects_stale_timestamp,
        test_decode_joiner_rejects_bad_pubkey,
        test_decode_joiner_rejects_short_key,
        test_encode_decode_host_full,
        test_encode_decode_host_minimal,
        test_decode_host_rejects_wrong_key,
        test_decode_host_rejects_stale_timestamp,
        test_decode_host_rejects_bad_pubkey,
        test_decode_host_rejects_garbage,
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
