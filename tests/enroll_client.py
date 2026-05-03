#!/usr/bin/env python3
"""Reference client for the wgrtc-enroll auto-enrollment protocol.

This is a Python implementation of the §4.4 enrollment protocol from
the wireguardrtc-android design doc.  It serves three purposes:

  1. Reference implementation that future client ports (Android, iOS,
     etc.) can compare against for wire-format correctness.
  2. Regression-test fixture for the daemon's server-side handler;
     used by the tests/10_*..15_* test suite.
  3. Admin diagnostic tool: `enroll_client.py wgrtc-enroll://...` runs
     a one-shot enrollment from any host and prints the resulting WG
     config.

Wire-format notes (cf. PLAN.md §4.4.6):

  - All enrollment messages travel inside the same WebRTC OFFER
    envelope used by signalling (the public PeerJS broker rejects
    non-OFFER-shaped messages).
  - The discriminator is the `kind` field in payload.metadata:
    "enroll" | "enroll_ok" | "enroll_err".
  - The client's WireGuard public key is in the *cleartext* outer
    envelope (so the server can derive the ECDH shared secret to
    decrypt).  This is fine: WG public keys are not secret.

Cryptographic primitives (cf. PLAN.md §4.4.2):

  shared      = X25519(C_priv, S_pub)            (32 bytes)
  enroll_key  = BLAKE2b(shared, key=LABEL_ENROLL, digest_size=32)
  final_key   = BLAKE2b(enroll_key, key=token,   digest_size=32)
  ciphertext  = secretbox(plaintext, key=final_key)

  LABEL_ENROLL = b"wg-peerjs/v1/enroll"

Usage:
  enroll_client.py wgrtc-enroll://v1?...
  enroll_client.py --uri wgrtc-enroll://v1?... [--timeout 30] [--device "Pixel 8"]
"""

import argparse
import asyncio
import base64
import hashlib
import json
import secrets
import sys
import time
import urllib.parse
from typing import Optional

try:
    import websockets
    from nacl.bindings import crypto_scalarmult, crypto_box_keypair
    from nacl.hash import blake2b as _nacl_blake2b
    from nacl.encoding import RawEncoder as _NaclRawEncoder
    from nacl.secret import SecretBox
except ImportError as e:
    sys.stderr.write(f"missing dependency: {e}\n"
                     "install with: pip install websockets pynacl\n")
    sys.exit(2)

PROTOCOL_VERSION = 1
LABEL_ENROLL = b"wg-peerjs/v1/enroll"
DEFAULT_TIMEOUT = 30.0


# ──────────────────────────────────────────────────────────────────────────
# Crypto helpers
# ──────────────────────────────────────────────────────────────────────────


def derive_final_key(client_priv: bytes, server_pub: bytes,
                     token: bytes) -> bytes:
    """Compute final_key = BLAKE2b(BLAKE2b(ECDH, key=LABEL), key=token)."""
    shared = crypto_scalarmult(client_priv, server_pub)
    enroll_key = _nacl_blake2b(shared, digest_size=32,
                               key=LABEL_ENROLL[:32],
                               encoder=_NaclRawEncoder)
    final_key = _nacl_blake2b(enroll_key, digest_size=32,
                              key=token,
                              encoder=_NaclRawEncoder)
    return final_key


def routing_id(pubkey_b64: str, salt: bytes) -> str:
    h = hashlib.sha256()
    h.update(pubkey_b64.encode("utf-8"))
    h.update(salt)
    return h.hexdigest()


# ──────────────────────────────────────────────────────────────────────────
# WebRTC OFFER envelope (must match daemon's build_offer_envelope)
# ──────────────────────────────────────────────────────────────────────────


def build_peerjs_sdp() -> str:
    sid = secrets.randbits(63)
    ufrag = secrets.token_hex(2)
    pwd = secrets.token_hex(12)
    fp = ":".join(f"{b:02X}" for b in secrets.token_bytes(32))
    return (
        "v=0\r\n"
        f"o=- {sid} 2 IN IP4 127.0.0.1\r\n"
        "s=-\r\n"
        "t=0 0\r\n"
        "a=group:BUNDLE 0\r\n"
        "a=extmap-allow-mixed\r\n"
        "a=msid-semantic: WMS\r\n"
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
        "c=IN IP4 0.0.0.0\r\n"
        f"a=ice-ufrag:{ufrag}\r\n"
        f"a=ice-pwd:{pwd}\r\n"
        "a=ice-options:trickle\r\n"
        f"a=fingerprint:sha-256 {fp}\r\n"
        "a=setup:actpass\r\n"
        "a=mid:0\r\n"
        "a=sctp-port:5000\r\n"
        "a=max-message-size:262144\r\n"
    )


def build_enroll_envelope(dst_routing_id: str, client_pub_b64: str,
                          ciphertext_b64: str) -> dict:
    conn_id = "dc_" + secrets.token_hex(6)
    return {
        "type": "OFFER",
        "dst": dst_routing_id,
        "payload": {
            "sdp": {"sdp": build_peerjs_sdp(), "type": "offer"},
            "type": "data",
            "connectionId": conn_id,
            "label": conn_id,
            "reliable": False,
            "serialization": "binary",
            "metadata": {
                "v": PROTOCOL_VERSION,
                "kind": "enroll",
                "client_pub": client_pub_b64,
                "blob": ciphertext_b64,
            },
        },
    }


def extract_enroll_response(message: dict) -> Optional[tuple]:
    """Return (kind, blob_b64) for ENROLL_OK / ENROLL_ERR, else None."""
    if not isinstance(message, dict):
        return None
    if message.get("type") != "OFFER":
        return None
    payload = message.get("payload")
    if not isinstance(payload, dict):
        return None
    md = payload.get("metadata")
    if not isinstance(md, dict):
        return None
    if md.get("v") != PROTOCOL_VERSION:
        return None
    kind = md.get("kind")
    if kind not in ("enroll_ok", "enroll_err"):
        return None
    blob = md.get("blob")
    if not isinstance(blob, str):
        return None
    return kind, blob


# ──────────────────────────────────────────────────────────────────────────
# URI parser for wgrtc-enroll://v1?...
# ──────────────────────────────────────────────────────────────────────────


def parse_enroll_uri(uri: str) -> dict:
    """Parse wgrtc-enroll://v1?pk=...&salt=...&broker=...&token=...&...

    Returns dict with:  pk (bytes), salt (bytes), broker (str), brokerkey
    (str), token (bytes), expires (int|None), server (str|None).
    Raises ValueError on malformed URI.
    """
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme != "wgrtc-enroll":
        raise ValueError(f"not a wgrtc-enroll:// URI: {uri!r}")
    if parsed.netloc != "v1":
        raise ValueError(f"unsupported version: {parsed.netloc!r} (expected v1)")
    qs = urllib.parse.parse_qs(parsed.query)

    def get_required(key):
        v = qs.get(key)
        if not v:
            raise ValueError(f"missing required field {key!r}")
        return v[0]

    def b64url_decode(s: str) -> bytes:
        # Re-pad as needed
        s = s.replace("-", "+").replace("_", "/")
        s += "=" * (-len(s) % 4)
        return base64.b64decode(s)

    return {
        "pk":         b64url_decode(get_required("pk")),
        "salt":       b64url_decode(get_required("salt")),
        "broker":     get_required("broker"),
        "brokerkey":  qs.get("brokerkey", ["peerjs"])[0],
        "token":      b64url_decode(get_required("token")),
        "expires":    int(qs["expires"][0]) if "expires" in qs else None,
        "server":     qs.get("server", [None])[0],
    }


# ──────────────────────────────────────────────────────────────────────────
# Enrollment client
# ──────────────────────────────────────────────────────────────────────────


async def enroll(uri_data: dict, *, device: str = "reference-client",
                 hint: str = "ref", timeout: float = DEFAULT_TIMEOUT,
                 client_keypair: Optional[tuple] = None) -> dict:
    """Run one ENROLL exchange.  Returns dict with:
        ok:       bool
        kind:     "enroll_ok" | "enroll_err" | "timeout"
        plaintext: dict on success, dict with code on err
        client_pub_b64: str (the keypair the client used)
        client_priv_b64: str
    """
    server_pub = uri_data["pk"]
    salt = uri_data["salt"]
    token = uri_data["token"]
    broker = uri_data["broker"]
    brokerkey = uri_data["brokerkey"]

    if uri_data.get("expires") and time.time() > uri_data["expires"]:
        return {"ok": False, "kind": "expired-locally",
                "plaintext": {"code": "TOKEN_EXPIRED",
                              "note": "expired before client started"}}

    # Generate keypair (or accept caller-supplied for tests).
    if client_keypair is None:
        # crypto_box_keypair returns (pubkey, secretkey) on Curve25519
        # in libsodium's box parameterisation.  These are valid X25519
        # keys and are the same shape WireGuard uses.
        c_pub, c_priv = crypto_box_keypair()
    else:
        c_pub, c_priv = client_keypair
    c_pub_b64 = base64.b64encode(c_pub).decode()
    c_priv_b64 = base64.b64encode(c_priv).decode()
    server_pub_b64 = base64.b64encode(server_pub).decode()

    final_key = derive_final_key(c_priv, server_pub, token)
    box = SecretBox(final_key)

    plaintext = {
        "v": PROTOCOL_VERSION,
        "ts": int(time.time()),
        "token_check": base64.b64encode(token).decode(),
        "hint": hint,
        "device": device,
        "client_caps": {"obfs": [], "transport": ["udp"]},
    }
    ciphertext = box.encrypt(json.dumps(plaintext).encode())
    ciphertext_b64 = base64.b64encode(ciphertext).decode()

    our_id = routing_id(c_pub_b64, salt)
    dst_id = routing_id(server_pub_b64, salt)

    sep = "&" if "?" in broker else "?"
    nonce = secrets.token_hex(8)
    ws_url = (f"{broker}{sep}key={brokerkey}&id={our_id}"
              f"&token={nonce}&version=1.5.2")

    envelope = build_enroll_envelope(dst_id, c_pub_b64, ciphertext_b64)

    deadline = asyncio.get_event_loop().time() + timeout
    async with websockets.connect(ws_url) as ws:
        # Wait for OPEN.
        raw = await asyncio.wait_for(ws.recv(),
                                     timeout=max(0.1, deadline - asyncio.get_event_loop().time()))
        first = json.loads(raw)
        if first.get("type") != "OPEN":
            return {"ok": False, "kind": "broker-error",
                    "plaintext": {"code": "BROKER_ERROR",
                                  "note": f"first message: {first}"}}

        # Send ENROLL.
        await ws.send(json.dumps(envelope))

        # Wait for ENROLL_OK or ENROLL_ERR.
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                return {"ok": False, "kind": "timeout",
                        "plaintext": {"code": "TIMEOUT",
                                      "note": "no response from server"},
                        "client_pub_b64": c_pub_b64,
                        "client_priv_b64": c_priv_b64}
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
            except asyncio.TimeoutError:
                return {"ok": False, "kind": "timeout",
                        "plaintext": {"code": "TIMEOUT"},
                        "client_pub_b64": c_pub_b64,
                        "client_priv_b64": c_priv_b64}
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            extracted = extract_enroll_response(msg)
            if extracted is None:
                continue
            kind, blob_b64 = extracted
            try:
                resp_plaintext = json.loads(box.decrypt(
                    base64.b64decode(blob_b64)).decode())
            except Exception as e:
                # Either a forged response we can't decrypt (attacker?)
                # or our key derivation is wrong.  Either way, abort.
                return {"ok": False, "kind": "decrypt-failed",
                        "plaintext": {"code": "DECRYPT_FAILED",
                                      "note": str(e)},
                        "client_pub_b64": c_pub_b64,
                        "client_priv_b64": c_priv_b64}
            return {"ok": kind == "enroll_ok",
                    "kind": kind,
                    "plaintext": resp_plaintext,
                    "client_pub_b64": c_pub_b64,
                    "client_priv_b64": c_priv_b64}


# ──────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("uri", nargs="?",
                    help="wgrtc-enroll://v1?... URI")
    ap.add_argument("--uri", dest="uri_alt",
                    help="(alternative) wgrtc-enroll URI as a flag")
    ap.add_argument("--device", default="reference-client",
                    help="device string sent in ENROLL plaintext")
    ap.add_argument("--hint", default="ref",
                    help="name hint sent in ENROLL plaintext")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                    help=f"seconds to wait for response (default {DEFAULT_TIMEOUT})")
    ap.add_argument("--json", action="store_true",
                    help="emit machine-readable JSON result on stdout")
    args = ap.parse_args()

    uri = args.uri or args.uri_alt
    if not uri:
        ap.error("URI is required (positional or --uri)")

    try:
        uri_data = parse_enroll_uri(uri)
    except ValueError as e:
        sys.stderr.write(f"bad URI: {e}\n")
        sys.exit(2)

    result = asyncio.run(enroll(uri_data,
                                device=args.device, hint=args.hint,
                                timeout=args.timeout))

    if args.json:
        # Strip private key from JSON output (don't pollute logs).
        out = dict(result)
        out.pop("client_priv_b64", None)
        print(json.dumps(out, indent=2))
    else:
        if result["ok"]:
            print(f"OK: enrolled, server returned:")
            for k, v in result["plaintext"].items():
                print(f"  {k}: {v}")
        else:
            print(f"FAILED ({result['kind']}):")
            for k, v in result["plaintext"].items():
                print(f"  {k}: {v}")

    sys.exit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
