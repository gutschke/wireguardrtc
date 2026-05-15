#!/usr/bin/env python3
# 45_wormhole_flow.py — wormhole-pairing flow controller.
#
# Pair two flows together over an in-memory async transport (no real
# broker).  Verify:
#  - both sides arrive at the same SPAKE2 shared key.
#  - both sides produce matching SAS phrases.
#  - both sides verify each other's confirm MAC.
#  - host's encrypted info blob decrypts cleanly on the joiner side.
#  - mismatched codes abort with MAC verification failure.
#  - aborted SAS confirmation returns a clear error.

import asyncio
import base64
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


class InMemoryTransport:
    """Two-ended transport for tests: each end's `send` shows up on
    the other end's inbound queue.  Mimics the broker minus delivery
    delay and message-loss handling."""

    def __init__(self):
        self.a_to_b = asyncio.Queue()
        self.b_to_a = asyncio.Queue()

    def end_a(self, src):
        return _End(self.a_to_b, self.b_to_a, src)

    def end_b(self, src):
        return _End(self.b_to_a, self.a_to_b, src)


class _End:
    def __init__(self, out_q, in_q, src):
        self._out = out_q
        self._in = in_q
        self._src = src

    async def send(self, envelope):
        # The broker fills in `src` on the way to the peer.  Replicate.
        envelope = dict(envelope)
        envelope["src"] = self._src
        await self._out.put(envelope)
        return True

    async def recv(self):
        return await self._in.get()

    async def close(self):
        pass


# ─── happy-path round trip ────────────────────────────────────────

def _run_pair(initiator_run, responder_run):
    """Helper: run two flows concurrently to completion."""

    async def go():
        transport = InMemoryTransport()
        a = transport.end_a(src="initiator-id")
        b = transport.end_b(src="responder-id")
        i_task = asyncio.create_task(initiator_run(a))
        r_task = asyncio.create_task(responder_run(b))
        return await asyncio.gather(i_task, r_task)

    return asyncio.run(go())


def test_happy_path_round_trip():
    code = "ABCDEF"
    code_bytes = wgrtc.wormhole_to_bytes(code)
    pubkey_b64 = base64.b64encode(bytes(32)).decode("ascii")

    async def initiator(end):
        flow = wgrtc.WormholeFlow(role="initiator", code_bytes=code_bytes,
                                   transport=end)
        # Joiner: sends joiner_info, receives host_info, returns (sas, host_info).
        sas, info = await flow.run_joiner(
            joiner_pubkey_b64=pubkey_b64,
            device_name="laptop",
            confirm_sas=lambda phrase: True,
        )
        return ("initiator", sas, info)

    async def responder(end):
        flow = wgrtc.WormholeFlow(role="responder", code_bytes=code_bytes,
                                   transport=end)
        # Host: receives joiner_info, sends host_info, returns (sas, joiner_info).
        sas, info = await flow.run_host(
            host_info=dict(
                wg_pubkey_b64=pubkey_b64,
                wg_endpoint="203.0.113.5:51820",
                assigned_address="10.99.0.2/32",
                allowed_ips="10.99.0.1/32",
                host_name="my-server",
            ),
            confirm_sas=lambda phrase: True,
        )
        return ("responder", sas, info)

    (i_role, i_sas, host_info), (r_role, r_sas, joiner_info) = \
        _run_pair(initiator, responder)
    assert i_role == "initiator"
    assert r_role == "responder"
    # Both sides displayed the same SAS phrase.
    assert i_sas == r_sas
    # Joiner side recovered the host's info blob.
    assert host_info["wg_endpoint"] == "203.0.113.5:51820"
    assert host_info["host_name"] == "my-server"
    # Host side recovered the joiner's info blob.
    assert joiner_info["wg_pubkey"] == pubkey_b64
    assert joiner_info["device_name"] == "laptop"


def test_aborted_sas_raises():
    code = "ABCDEF"
    code_bytes = wgrtc.wormhole_to_bytes(code)
    pubkey_b64 = base64.b64encode(bytes(32)).decode("ascii")

    async def initiator(end):
        flow = wgrtc.WormholeFlow(role="initiator", code_bytes=code_bytes,
                                   transport=end)
        try:
            await flow.run_joiner(
                joiner_pubkey_b64=pubkey_b64,
                confirm_sas=lambda phrase: False,  # user aborts
            )
            raise AssertionError("expected SasAborted")
        except wgrtc.SasAborted:
            return "initiator-aborted"

    async def responder(end):
        flow = wgrtc.WormholeFlow(role="responder", code_bytes=code_bytes,
                                   transport=end)
        # Responder side: expect counter-party to abort.  We don't
        # know if the inbound abort arrives as a missing confirm or
        # something else; in our in-memory transport it just means
        # we get canceled.  Wrap in shielded close.
        try:
            await asyncio.wait_for(flow.run_host(
                host_info=dict(
                    wg_pubkey_b64=pubkey_b64,
                    wg_endpoint="x:1",
                    assigned_address="10.0.0.2/32",
                    allowed_ips="10.0.0.1/32",
                ),
                confirm_sas=lambda phrase: True,
            ), timeout=1.0)
            raise AssertionError("host expected to time out / abort")
        except (asyncio.TimeoutError, wgrtc.SasAborted, wgrtc.WormholeFailed):
            return "responder-timed-out"

    res = _run_pair(initiator, responder)
    assert res[0] == "initiator-aborted"
    assert res[1] == "responder-timed-out"


def test_mismatched_codes_reject():
    """Joiner types the wrong code → SPAKE2 still completes but the
    confirm-MAC verification fails: the keys are different, so the
    MAC over the wrong-K can't validate.  In production the broker
    would close both sessions when one side errors; in our in-memory
    test we have to bound each side with a wait_for so the side
    waiting for an enroll-info reply doesn't hang when the peer
    rejects its MAC."""
    pubkey_b64 = base64.b64encode(bytes(32)).decode("ascii")

    async def initiator(end):
        flow = wgrtc.WormholeFlow(role="initiator",
                                   code_bytes=wgrtc.wormhole_to_bytes("WRONG1"),
                                   transport=end)
        try:
            await asyncio.wait_for(flow.run_joiner(
                joiner_pubkey_b64=pubkey_b64,
                confirm_sas=lambda phrase: True,
            ), timeout=1.5)
            raise AssertionError("expected WormholeFailed on bad MAC")
        except (asyncio.TimeoutError, wgrtc.WormholeFailed):
            return "initiator-rejected"

    async def responder(end):
        flow = wgrtc.WormholeFlow(role="responder",
                                   code_bytes=wgrtc.wormhole_to_bytes("ABCDEF"),
                                   transport=end)
        try:
            await asyncio.wait_for(flow.run_host(
                host_info=dict(
                    wg_pubkey_b64=pubkey_b64,
                    wg_endpoint="x:1",
                    assigned_address="10.0.0.2/32",
                    allowed_ips="10.0.0.1/32",
                ),
                confirm_sas=lambda phrase: True,
            ), timeout=1.5)
            raise AssertionError("host expected to fail")
        except (asyncio.TimeoutError, wgrtc.WormholeFailed):
            return "responder-rejected"

    res = _run_pair(initiator, responder)
    assert "rejected" in res[0]
    assert "rejected" in res[1]


# ─── Driver ──────────────────────────────────────────────────────

def main():
    tests = [
        test_happy_path_round_trip,
        test_aborted_sas_raises,
        test_mismatched_codes_reject,
    ]
    failures = 0
    for t in tests:
        try:
            t()
            print(f"  ✓ {t.__name__}")
        except Exception as e:
            import traceback
            print(f"  ✗ {t.__name__}: {e}")
            traceback.print_exc()
            failures += 1
    print()
    print(f"{len(tests) - failures}/{len(tests)} passed")
    sys.exit(0 if failures == 0 else 1)


if __name__ == "__main__":
    main()
