#!/usr/bin/env python3
# _signal_wake_probe.py — used by tests/23 + 24.  Plays the role of a
# peer that sends a single signalling-OFFER (or signal_wake) to the
# daemon via the broker, then prints the daemon's responsive OFFER's
# decrypted plaintext on stdout (or "error:..." on stdout if the
# round-trip fails).
#
# Inputs come via environment variables so the shell test driver
# doesn't have to escape Python literals through nested
# fabric_exec_capture quoting:
#
#   PROBE_BROKER       = ws://192.168.99.10:9000/peerjs
#   PROBE_BROKER_KEY   = e2etestkey
#   PROBE_SALT_B64     = std-base64 32 bytes
#   PROBE_SRV_PUB_B64  = std-base64 32 bytes
#   PROBE_PEER_PRIV    = std-base64 32 bytes
#   PROBE_PEER_PUB     = std-base64 32 bytes
#   PROBE_KIND         = "signal_wake" or empty/"offer" (default empty)
#   PROBE_CANDIDATES   = JSON array body, e.g. '[{"ip":"1.2.3.4","port":51820,"kind":"stun"}]'
#                        (default "[]")
#   PROBE_TIMEOUT      = float seconds, default 5

import asyncio, base64, hashlib, json, os, secrets, sys, time
import nacl.bindings as nb
from nacl.secret import SecretBox
from nacl.hash import blake2b
from nacl.encoding import RawEncoder
import websockets

PROTOCOL_LABEL = b"wg-peerjs/v1/sigbox"


def routing_id(pub_b64, salt):
    h = hashlib.sha256()
    h.update(pub_b64.encode())
    h.update(salt)
    return h.hexdigest()


def sigbox_key(my_priv, their_pub):
    sh = nb.crypto_scalarmult(my_priv, their_pub)
    return blake2b(sh, digest_size=32, key=PROTOCOL_LABEL[:32], encoder=RawEncoder)


async def main():
    broker = os.environ["PROBE_BROKER"]
    broker_key = os.environ["PROBE_BROKER_KEY"]
    # The daemon stores `salt` as the UTF-8 bytes of the conf's
    # `Salt = <base64>` string — NOT the decoded 32-byte secret.
    # Routing-id is computed over those exact bytes; the URI carries
    # them under URL-safe-base64-no-pad as `salt=...`.  Match the
    # daemon's convention: pass through as bytes, don't re-decode.
    salt = os.environ["PROBE_SALT_B64"].encode("utf-8")
    srv_pub_b64 = os.environ["PROBE_SRV_PUB_B64"].strip()
    srv_pub = base64.b64decode(srv_pub_b64)
    peer_priv = base64.b64decode(os.environ["PROBE_PEER_PRIV"].strip())
    peer_pub_b64 = os.environ["PROBE_PEER_PUB"].strip()
    kind = os.environ.get("PROBE_KIND", "")
    candidates_json = os.environ.get("PROBE_CANDIDATES", "[]")
    timeout = float(os.environ.get("PROBE_TIMEOUT", "5"))

    key = sigbox_key(peer_priv, srv_pub)
    plain = {
        "v": 1, "ts": int(time.time()),
        "candidates": json.loads(candidates_json),
    }
    blob = base64.b64encode(SecretBox(key).encrypt(json.dumps(plain).encode())).decode()

    cid = "dc_" + secrets.token_hex(6)
    metadata = {"v": 1, "blob": blob}
    if kind:
        metadata["kind"] = kind

    envelope = {
        "type": "OFFER",
        "dst": routing_id(srv_pub_b64, salt),
        "payload": {
            "sdp": {"sdp": "stub", "type": "offer"},
            "type": "data", "connectionId": cid, "label": cid,
            "reliable": False, "serialization": "binary",
            "metadata": metadata,
        },
    }

    our_id = routing_id(peer_pub_b64, salt)
    nonce = secrets.token_hex(8)
    sep = "&" if "?" in broker else "?"
    uri = f"{broker}{sep}key={broker_key}&id={our_id}&token={nonce}&version=1.5.2"

    async with websockets.connect(uri) as ws:
        first_raw = await asyncio.wait_for(ws.recv(), timeout=5)
        first = json.loads(first_raw)
        if first.get("type") != "OPEN":
            print(f"error:no-open:{first!r}")
            return
        await ws.send(json.dumps(envelope))
        # Accept any number of intervening broker housekeeping
        # messages (e.g. HEARTBEAT echoes); look for the first OFFER.
        deadline = asyncio.get_event_loop().time() + timeout
        resp = None
        while asyncio.get_event_loop().time() < deadline:
            try:
                remaining = deadline - asyncio.get_event_loop().time()
                resp_raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
            except asyncio.TimeoutError:
                print("error:no-response")
                return
            try:
                m = json.loads(resp_raw)
            except Exception:
                continue
            if m.get("type") == "OFFER":
                resp = m
                break
            # else: HEARTBEAT, ID-TAKEN, etc. — keep waiting.
        if resp is None:
            print("error:no-offer-arrived")
            return
        md = resp.get("payload", {}).get("metadata", {})
        rblob = md.get("blob")
        if not isinstance(rblob, str):
            print("error:no-blob")
            return
        try:
            rct = base64.b64decode(rblob)
            rplain = SecretBox(key).decrypt(rct).decode()
        except Exception as e:
            print(f"error:decrypt-failed:{e}")
            return
        print(f"ok:{rplain}")


if __name__ == "__main__":
    asyncio.run(main())
