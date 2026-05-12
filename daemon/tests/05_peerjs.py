#!/usr/bin/env python3
"""
Verify PeerJS broker protocol assumptions, end-to-end.

Diagnostic edition: opens TWO short-lived connections and tries the OFFER
forward. Every message received on either side is logged, with timestamps,
so a forwarding failure tells us *what the broker is doing* instead of just
that nothing arrived. Tries multiple message-shape variants in case the
broker is picky:

    variant 1: bare         {type:OFFER, dst:B, payload:"<str>"}
    variant 2: object payload   {..., payload:{label:"wg-peerjs-test"}}
    variant 3: with version field on URL  (?version=1.5.5)
    variant 4: with HEARTBEAT pacing during the wait

The previous run on the public broker showed both ends getting OPEN but B
never receiving A's OFFER. This version pinpoints whether it's the version
gate, payload shape, listener race, or silent rate-limit.

Be a good citizen: total runtime ~25 s, 2 concurrent connections, randomized
64-char hex IDs. No retry storm.

Usage:  ./venv/bin/python tests/05_peerjs.py
        ./venv/bin/python tests/05_peerjs.py --server wss://your-self-hosted/peerjs
        ./venv/bin/python tests/05_peerjs.py --idle-test
"""

import argparse
import asyncio
import json
import os
import sys
import time

try:
    import websockets
except ImportError:
    print("Need the `websockets` package.")
    print("Re-run from the daemon's venv, e.g.:")
    print("  ./venv/bin/python tests/05_peerjs.py")
    sys.exit(2)


def random_id():
    return os.urandom(32).hex()


def peerjs_style_id():
    """Mimic the broker's default ID generator: 10-char alphanumeric, no
    underscores. Some abuse filters key on the ID format."""
    import string, random as _rnd
    alphabet = string.ascii_letters + string.digits
    return "".join(_rnd.choice(alphabet) for _ in range(10))


def peerjs_token():
    """Mimic the browser's token format: ~11 lowercase alphanumeric chars."""
    import string, random as _rnd
    alphabet = string.ascii_lowercase + string.digits
    return "".join(_rnd.choice(alphabet) for _ in range(11))


def peerjs_offer_payload(cookie):
    """Build an OFFER payload that looks like a real WebRTC datachannel
    negotiation (because the public broker / its WAF inspects shape).

    Encrypted application data (in our real daemon, this would be the
    NaCl-Box-encrypted WG endpoint) is tucked into `metadata.wg`.
    """
    # SDP fields that vary per call.
    session_id = "".join("0123456789"[b % 10] for b in os.urandom(19))
    ice_ufrag = os.urandom(3).hex()[:4]
    ice_pwd = os.urandom(18).hex()[:24]
    fp = ":".join(f"{b:02X}" for b in os.urandom(32))
    conn_id = "dc_" + os.urandom(6).hex()[:11]
    sdp = (
        "v=0\r\n"
        f"o=- {session_id} 2 IN IP4 127.0.0.1\r\n"
        "s=-\r\n"
        "t=0 0\r\n"
        "a=group:BUNDLE 0\r\n"
        "a=extmap-allow-mixed\r\n"
        "a=msid-semantic: WMS\r\n"
        "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"
        "c=IN IP4 0.0.0.0\r\n"
        f"a=ice-ufrag:{ice_ufrag}\r\n"
        f"a=ice-pwd:{ice_pwd}\r\n"
        "a=ice-options:trickle\r\n"
        f"a=fingerprint:sha-256 {fp}\r\n"
        "a=setup:actpass\r\n"
        "a=mid:0\r\n"
        "a=sctp-port:5000\r\n"
        "a=max-message-size:262144\r\n"
    )
    return {
        "sdp": {"sdp": sdp, "type": "offer"},
        "type": "data",
        "connectionId": conn_id,
        "label": conn_id,
        "reliable": False,
        "serialization": "binary",
        "metadata": {"test_cookie": cookie},
    }


def build_uri(server, key, peer_id, version=None):
    token = os.urandom(8).hex()
    sep = "&" if "?" in server else "?"
    uri = f"{server}{sep}key={key}&id={peer_id}&token={token}"
    if version:
        uri += f"&version={version}"
    return uri


async def listener_loop(ws, label, log, stop_event):
    """Drain everything the server sends on this socket; tag with timestamps."""
    while not stop_event.is_set():
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=1.0)
        except asyncio.TimeoutError:
            continue
        except websockets.exceptions.ConnectionClosed as e:
            log.append((time.monotonic(), label, "CLOSED", f"code={e.code} reason={e.reason!r}"))
            return
        try:
            msg = json.loads(raw)
        except Exception:
            log.append((time.monotonic(), label, "RAW", raw[:200]))
            continue
        log.append((time.monotonic(), label, "RECV", msg))


async def heartbeat_loop(ws, label, log, stop_event, interval=5.0, prime=True):
    """Send PeerJS heartbeats. If prime=True, send one immediately (the
    reference peerjs client schedules its first HEARTBEAT effectively at
    connection time, so a broker that gates on liveness sees it within ~ms,
    not after a 5 s wait)."""
    if prime:
        try:
            await ws.send(json.dumps({"type": "HEARTBEAT"}))
            log.append((time.monotonic(), label, "SENT", {"type": "HEARTBEAT (priming)"}))
        except Exception as e:
            log.append((time.monotonic(), label, "HB-FAIL", str(e)))
            return
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(asyncio.sleep(interval), timeout=interval + 1)
        except asyncio.TimeoutError:
            pass
        if stop_event.is_set():
            return
        try:
            await ws.send(json.dumps({"type": "HEARTBEAT"}))
            log.append((time.monotonic(), label, "SENT", {"type": "HEARTBEAT"}))
        except Exception as e:
            log.append((time.monotonic(), label, "HB-FAIL", str(e)))
            return


async def open_and_wait_for_open(uri, label, log, timeout=5.0,
                                 extra_headers=None):
    log.append((time.monotonic(), label, "CONNECT", uri))
    # `additional_headers` works on websockets >=11; older releases used
    # `extra_headers`. Try the new name, fall back if necessary.
    connect_kwargs = {}
    if extra_headers:
        try:
            ws = await asyncio.wait_for(
                websockets.connect(uri, additional_headers=extra_headers),
                timeout=timeout,
            )
        except TypeError:
            ws = await asyncio.wait_for(
                websockets.connect(uri, extra_headers=extra_headers),
                timeout=timeout,
            )
    else:
        ws = await asyncio.wait_for(websockets.connect(uri), timeout=timeout)
    raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
    msg = json.loads(raw)
    log.append((time.monotonic(), label, "RECV", msg))
    if msg.get("type") != "OPEN":
        raise RuntimeError(f"expected OPEN, got {msg}")
    return ws


async def variant_run(server, key, version, payload_shape, settle_seconds, args,
                      extra_headers=None, hdr_label="", id_style="hex"):
    """One full attempt at A->B OFFER under a given variant."""
    if id_style == "peerjs":
        a_id, b_id = peerjs_style_id(), peerjs_style_id()
        a_token, b_token = peerjs_token(), peerjs_token()
        a_uri = (f"{server}{'&' if '?' in server else '?'}"
                 f"key={key}&id={a_id}&token={a_token}"
                 + (f"&version={version}" if version else ""))
        b_uri = (f"{server}{'&' if '?' in server else '?'}"
                 f"key={key}&id={b_id}&token={b_token}"
                 + (f"&version={version}" if version else ""))
    else:
        a_id, b_id = random_id(), random_id()
        a_uri = build_uri(server, key, a_id, version=version)
        b_uri = build_uri(server, key, b_id, version=version)

    log = []
    t0 = time.monotonic()
    print(f"\n--- variant: version={version!r} payload={payload_shape} "
          f"settle={settle_seconds}s{(' headers=' + hdr_label) if hdr_label else ''}")
    print(f"  A id={a_id[:16]}... B id={b_id[:16]}...")

    try:
        ws_a, ws_b = await asyncio.gather(
            open_and_wait_for_open(a_uri, "A", log, extra_headers=extra_headers),
            open_and_wait_for_open(b_uri, "B", log, extra_headers=extra_headers),
        )
    except Exception as e:
        print(f"  CONNECT FAILED: {e!r}")
        for entry in log:
            ts, lbl, kind, body = entry
            print(f"    [{ts-t0:6.3f}s] {lbl} {kind}: {body}")
        return False

    stop = asyncio.Event()
    drain_a = asyncio.create_task(listener_loop(ws_a, "A", log, stop))
    drain_b = asyncio.create_task(listener_loop(ws_b, "B", log, stop))
    # Prime heartbeats *immediately* so the broker sees liveness before our OFFER.
    hb_a = asyncio.create_task(heartbeat_loop(ws_a, "A", log, stop, prime=True))
    hb_b = asyncio.create_task(heartbeat_loop(ws_b, "B", log, stop, prime=True))

    # Settle with primed heartbeats so the broker registers both clients
    # and observes liveness before we transmit.
    await asyncio.sleep(settle_seconds)

    cookie = os.urandom(6).hex()
    if payload_shape == "string":
        payload = json.dumps({"test_cookie": cookie})
    elif payload_shape == "object":
        # Mimic a partial client OFFER body (label/reliable/serialization).
        payload = {
            "label": f"wg-peerjs-probe-{cookie}",
            "reliable": True,
            "serialization": "binary",
            "metadata": {"test_cookie": cookie},
        }
    elif payload_shape == "webrtc":
        # Fully WebRTC-shaped: SDP wrapper, connectionId, the works.
        payload = peerjs_offer_payload(cookie)
    else:
        raise ValueError(payload_shape)

    msg = {"type": "OFFER", "dst": b_id, "payload": payload}
    log.append((time.monotonic(), "A", "SENT", msg))
    await ws_a.send(json.dumps(msg))

    # Listen for up to 8s for any forwarded message on B.
    received_offer = False
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        await asyncio.sleep(0.2)
        for entry in log:
            ts, lbl, kind, body = entry
            if (lbl == "B" and kind == "RECV"
                    and isinstance(body, dict) and body.get("type") == "OFFER"
                    and cookie in json.dumps(body)):
                received_offer = True
                break
        if received_offer:
            break

    stop.set()
    for t in (drain_a, drain_b, hb_a, hb_b):
        t.cancel()
        try:
            await t
        except (asyncio.CancelledError, Exception):
            pass
    try:
        await ws_a.close()
        await ws_b.close()
    except Exception:
        pass

    print(f"  RESULT: {'OFFER delivered to B' if received_offer else 'OFFER LOST'}")
    print("  full transcript:")
    for entry in log:
        ts, lbl, kind, body = entry
        body_repr = body
        if isinstance(body, dict):
            short = dict(body)
            for big_field in ("payload",):
                if big_field in short and isinstance(short[big_field], str) and len(short[big_field]) > 80:
                    short[big_field] = short[big_field][:80] + "..."
            body_repr = short
        print(f"    [{ts-t0:6.3f}s] {lbl:>3s} {kind:8s} {body_repr}")
    return received_offer


async def measure_idle_tolerance(uri, label, max_wait=70.0):
    print(f"\n[idle] {label} connecting and going silent (max wait {max_wait:.0f}s)...")
    ws = await asyncio.wait_for(websockets.connect(uri), timeout=5.0)
    start = time.monotonic()
    try:
        try:
            first = await asyncio.wait_for(ws.recv(), timeout=5.0)
            print(f"[idle] OPEN: {first}")
        except asyncio.TimeoutError:
            pass
        while True:
            try:
                msg = await asyncio.wait_for(
                    ws.recv(),
                    timeout=max_wait - (time.monotonic() - start),
                )
                print(f"[idle] +{time.monotonic()-start:.1f}s server sent: {msg}")
            except asyncio.TimeoutError:
                print(f"[idle] still alive after {max_wait:.0f}s — stopping wait")
                break
    except websockets.exceptions.ConnectionClosed as e:
        print(f"[idle] server closed after {time.monotonic()-start:.1f}s "
              f"(code={e.code} reason={e.reason!r})")
    finally:
        try:
            await ws.close()
        except Exception:
            pass


async def main_async(args):
    server = args.server
    key = args.key
    print(f"PeerJS server: {server}")
    print(f"key:           {key}")

    # Header bundles to test against the broker. The "browser-like" set is
    # what a vanilla Chrome on peerjs.com would send; the "origin-only" set
    # isolates whether the Origin header alone is the gate.
    BROWSER_HEADERS = [
        ("Origin", "https://peerjs.com"),
        ("User-Agent",
         "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
         "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
    ]
    ORIGIN_ONLY = [("Origin", "https://peerjs.com")]
    UA_ONLY = [("User-Agent",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")]

    variants = [
        # (version, payload_shape, settle, extra_headers, header_label, id_style)
        # Bare baselines (already known to fail on public broker):
        (None,    "string",  0.5, None,            "none",   "hex"),
        ("1.5.5", "object",  0.5, BROWSER_HEADERS, "browser","hex"),
        # The new hypothesis (browser sends WebRTC-shaped payload). If
        # this passes on the public broker, the wire-format gate is the
        # SDP-shaped OFFER body, not the headers or timing.
        ("1.5.2", "webrtc",  0.5, BROWSER_HEADERS, "browser","peerjs"),
        ("1.5.2", "webrtc",  0.5, BROWSER_HEADERS, "browser","hex"),
        ("1.5.2", "webrtc",  0.5, None,            "none",   "peerjs"),
    ]
    results = []
    for version, payload_shape, settle, hdrs, hdr_label, id_style in variants:
        ok = await variant_run(server, key, version, payload_shape, settle, args,
                               extra_headers=hdrs, hdr_label=hdr_label,
                               id_style=id_style)
        results.append((version, payload_shape, settle, hdr_label, id_style, ok))
        # Don't hammer the broker: small pause between variants.
        await asyncio.sleep(2.0)

    print("\n=== summary ===")
    for version, payload_shape, settle, hdr_label, id_style, ok in results:
        marker = "PASS" if ok else "LOST"
        print(f"  version={str(version):8s} payload={payload_shape:7s} "
              f"settle={settle:>4.1f}s hdr={hdr_label:8s} id={id_style:7s} -> {marker}")

    if args.idle_test:
        await measure_idle_tolerance(
            build_uri(server, key, random_id(), version="1.5.5"),
            "C",
            max_wait=70.0,
        )

    if any(ok for *_, ok in results):
        print("\nAt least one variant works; daemon should adopt that wire format.")
        sys.exit(0)
    print("\nAll variants failed. Either:")
    print("  * the broker has additional gating (rate limit, abuse filter,")
    print("    require pre-handshake), or")
    print("  * the broker is currently unhealthy. Try a self-hosted instance:")
    print("      docker run -p9000:9000 peerjs/peerjs-server --port 9000")
    print("    then: ./venv/bin/python tests/05_peerjs.py --server ws://127.0.0.1:9000/peerjs")
    sys.exit(1)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--server", default="wss://0.peerjs.com/peerjs")
    ap.add_argument("--key", default="peerjs")
    ap.add_argument("--idle-test", action="store_true")
    args = ap.parse_args()
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
