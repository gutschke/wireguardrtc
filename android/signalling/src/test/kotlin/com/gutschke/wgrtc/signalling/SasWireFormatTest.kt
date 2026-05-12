package com.gutschke.wgrtc.signalling

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.util.Base64

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SasWireFormatTest {

    @BeforeAll fun installJvmSodium() {
        Sodium.setForTest(LazySodiumJava(SodiumJava()))
    }
    @AfterAll fun restoreSodium() { Sodium.setForTest(null) }

    // ─── routing-id derivation ────────────────────────────────────

    @Test fun `routing ids differ between roles for the same code`() {
        val code = "moose-lantern-7".toByteArray()
        val a = sasRoutingIdInitiator(code)
        val b = sasRoutingIdResponder(code)
        assertNotEquals(a, b, "roles must subscribe to different inboxes")
    }

    @Test fun `routing id is deterministic`() {
        val code = "moose-lantern-7".toByteArray()
        assertEquals(sasRoutingIdInitiator(code), sasRoutingIdInitiator(code))
        assertEquals(sasRoutingIdResponder(code), sasRoutingIdResponder(code))
    }

    @Test fun `different codes produce different routing ids`() {
        val a = sasRoutingIdInitiator("alpha".toByteArray())
        val b = sasRoutingIdInitiator("beta".toByteArray())
        assertNotEquals(a, b)
    }

    @Test fun `routing id is URL-safe-base64 with no padding`() {
        val code = "code".toByteArray()
        val id = sasRoutingIdInitiator(code)
        // URL-safe alphabet: A-Z a-z 0-9 - _. No '+', '/', or '='.
        assertTrue(id.all { it.isLetterOrDigit() || it == '-' || it == '_' },
            "expected URL-safe-base64, got: $id")
        assertFalse(id.contains('='))
    }

    // ─── step-1 envelope round-trip ───────────────────────────────

    @Test fun `step1 round-trips through build then extract`() {
        val pakeMsg = ByteArray(32) { it.toByte() }
        val env = buildSasStep1Envelope(dstRoutingId = "dst-init", pakeMsg = pakeMsg)
            .let { withSrc(it, "alice-src") }
        val parsed = extractSasStep1(env)!!
        assertEquals("alice-src", parsed.src)
        assertArrayEquals(pakeMsg, parsed.pakeMsg)
    }

    @Test fun `step2 round-trips through build then extract`() {
        val pakeMsg = ByteArray(32) { (0xff - it).toByte() }
        val env = buildSasStep2Envelope("dst-resp", pakeMsg)
            .let { withSrc(it, "bob-src") }
        val parsed = extractSasStep2(env)!!
        assertEquals("bob-src", parsed.src)
        assertArrayEquals(pakeMsg, parsed.pakeMsg)
    }

    @Test fun `step1 extractor refuses step2 envelope and vice versa`() {
        val msg = ByteArray(32) { 1 }
        val env1 = withSrc(buildSasStep1Envelope("dst", msg), "x")
        val env2 = withSrc(buildSasStep2Envelope("dst", msg), "x")
        assertNull(extractSasStep1(env2))
        assertNull(extractSasStep2(env1))
    }

    @Test fun `step1 build rejects wrong-size pakeMsg`() {
        assertThrows(IllegalArgumentException::class.java) {
            buildSasStep1Envelope("dst", ByteArray(31))
        }
        assertThrows(IllegalArgumentException::class.java) {
            buildSasStep1Envelope("dst", ByteArray(33))
        }
    }

    @Test fun `step2 build rejects wrong-size pakeMsg`() {
        assertThrows(IllegalArgumentException::class.java) {
            buildSasStep2Envelope("dst", ByteArray(0))
        }
    }

    @Test fun `extract returns null for missing pake_msg`() {
        // Build a valid step1 envelope, then strip the pake_msg
        // field from metadata to confirm strict-extraction.
        val env = withSrc(buildSasStep1Envelope("dst", ByteArray(32)), "x") as JsonObject
        val mutated = mutateMetadata(env) { meta ->
            buildJsonObject {
                meta.entries.forEach { (k, v) -> if (k != "pake_msg") put(k, v) }
            }
        }
        assertNull(extractSasStep1(mutated))
    }

    @Test fun `extract returns null for malformed base64 pake_msg`() {
        val env = withSrc(buildSasStep1Envelope("dst", ByteArray(32)), "x") as JsonObject
        val mutated = mutateMetadata(env) { meta ->
            buildJsonObject {
                meta.entries.forEach { (k, v) ->
                    if (k == "pake_msg") put(k, "not!valid!base64!")
                    else put(k, v)
                }
            }
        }
        assertNull(extractSasStep1(mutated))
    }

    @Test fun `extract returns null for wrong-length pake_msg`() {
        val short = Base64.getEncoder().encodeToString(ByteArray(16))
        val env = withSrc(buildSasStep1Envelope("dst", ByteArray(32)), "x") as JsonObject
        val mutated = mutateMetadata(env) { meta ->
            buildJsonObject {
                meta.entries.forEach { (k, v) ->
                    if (k == "pake_msg") put(k, short)
                    else put(k, v)
                }
            }
        }
        assertNull(extractSasStep1(mutated))
    }

    @Test fun `extract returns null when src is missing`() {
        val env = buildSasStep1Envelope("dst", ByteArray(32)) // no src injected
        assertNull(extractSasStep1(env))
    }

    @Test fun `extract returns null on version mismatch`() {
        val env = withSrc(buildSasStep1Envelope("dst", ByteArray(32)), "x") as JsonObject
        val mutated = mutateMetadata(env) { meta ->
            buildJsonObject {
                meta.entries.forEach { (k, v) ->
                    if (k == "v") put(k, 999)
                    else put(k, v)
                }
            }
        }
        assertNull(extractSasStep1(mutated))
    }

    @Test fun `extract returns null on non-OFFER type`() {
        val env = withSrc(buildSasStep1Envelope("dst", ByteArray(32)), "x") as JsonObject
        val replaced = buildJsonObject {
            env.entries.forEach { (k, v) ->
                if (k == "type") put(k, "ANSWER")
                else put(k, v)
            }
        }
        assertNull(extractSasStep1(replaced))
    }

    // ─── confirm envelope ─────────────────────────────────────────

    @Test fun `confirm round-trips through build then extract`() {
        val mac = ByteArray(SAS_CONFIRM_MAC_LEN) { it.toByte() }
        val env = withSrc(buildSasConfirmEnvelope("dst", mac), "src-id")
        val parsed = extractSasConfirm(env)!!
        assertEquals("src-id", parsed.src)
        assertArrayEquals(mac, parsed.mac)
        assertNull(parsed.encryptedInfo,
            "info field is optional; absent in mac-only confirm")
    }

    @Test fun `confirm carries optional encrypted info round-trip`() {
        val mac = ByteArray(SAS_CONFIRM_MAC_LEN) { 1 }
        val info = "encrypted-payload-bytes".toByteArray()
        val env = withSrc(
            buildSasConfirmEnvelope("dst", mac, encryptedInfo = info),
            "src",
        )
        val parsed = extractSasConfirm(env)!!
        assertArrayEquals(info, parsed.encryptedInfo!!)
    }

    @Test fun `confirm with malformed info base64 returns null`() {
        val mac = ByteArray(SAS_CONFIRM_MAC_LEN) { 2 }
        val env = withSrc(buildSasConfirmEnvelope("dst", mac), "src") as JsonObject
        val mutated = mutateMetadata(env) { meta ->
            buildJsonObject {
                meta.entries.forEach { (k, v) -> put(k, v) }
                put("info", "not!valid!base64!")
            }
        }
        assertNull(extractSasConfirm(mutated))
    }

    @Test fun `confirm build rejects wrong-size mac`() {
        assertThrows(IllegalArgumentException::class.java) {
            buildSasConfirmEnvelope("dst", ByteArray(SAS_CONFIRM_MAC_LEN - 1))
        }
        assertThrows(IllegalArgumentException::class.java) {
            buildSasConfirmEnvelope("dst", ByteArray(SAS_CONFIRM_MAC_LEN + 1))
        }
    }

    @Test fun `confirm extractor refuses step envelope`() {
        val env = withSrc(buildSasStep1Envelope("dst", ByteArray(32)), "x")
        assertNull(extractSasConfirm(env))
    }

    @Test fun `confirm extractor refuses wrong-size mac in metadata`() {
        val env = withSrc(buildSasConfirmEnvelope("dst",
            ByteArray(SAS_CONFIRM_MAC_LEN)), "x") as JsonObject
        val short = Base64.getEncoder().encodeToString(ByteArray(8))
        val mutated = mutateMetadata(env) { meta ->
            buildJsonObject {
                meta.entries.forEach { (k, v) ->
                    if (k == "mac") put(k, short)
                    else put(k, v)
                }
            }
        }
        assertNull(extractSasConfirm(mutated))
    }

    // ─── confirm-MAC crypto ───────────────────────────────────────

    @Test fun `MAC differs between roles for the same key`() {
        val key = ByteArray(32) { 7 }
        val initMac = buildSasConfirmMac(SasConfirmRole.INITIATOR, key)
        val respMac = buildSasConfirmMac(SasConfirmRole.RESPONDER, key)
        assertEquals(SAS_CONFIRM_MAC_LEN, initMac.size)
        assertEquals(SAS_CONFIRM_MAC_LEN, respMac.size)
        assertFalse(initMac.contentEquals(respMac),
            "role separation must produce different MACs")
    }

    @Test fun `MAC differs between keys for the same role`() {
        val k1 = ByteArray(32) { 1 }
        val k2 = ByteArray(32) { 2 }
        val m1 = buildSasConfirmMac(SasConfirmRole.INITIATOR, k1)
        val m2 = buildSasConfirmMac(SasConfirmRole.INITIATOR, k2)
        assertFalse(m1.contentEquals(m2))
    }

    @Test fun `verify accepts a peer-role MAC computed with the same key`() {
        val key = ByteArray(32) { 9 }
        // Local side is initiator; peer is responder; we send our
        // initiator-MAC and verify the peer's responder-MAC.
        val peerMac = buildSasConfirmMac(SasConfirmRole.RESPONDER, key)
        assertTrue(verifySasConfirmMac(SasConfirmRole.RESPONDER, key, peerMac))
    }

    @Test fun `verify rejects same-role MAC (catches role-confusion bugs)`() {
        val key = ByteArray(32) { 9 }
        val ourMac = buildSasConfirmMac(SasConfirmRole.INITIATOR, key)
        assertFalse(verifySasConfirmMac(SasConfirmRole.RESPONDER, key, ourMac),
            "verifying our own role's MAC under the peer's role must fail")
    }

    @Test fun `verify rejects MAC from a different key`() {
        val key1 = ByteArray(32) { 1 }
        val key2 = ByteArray(32) { 2 }
        val mac = buildSasConfirmMac(SasConfirmRole.RESPONDER, key1)
        assertFalse(verifySasConfirmMac(SasConfirmRole.RESPONDER, key2, mac))
    }

    @Test fun `verify rejects wrong-size MAC`() {
        val key = ByteArray(32) { 9 }
        assertFalse(verifySasConfirmMac(
            SasConfirmRole.RESPONDER, key, ByteArray(SAS_CONFIRM_MAC_LEN - 1)))
        assertFalse(verifySasConfirmMac(
            SasConfirmRole.RESPONDER, key, ByteArray(SAS_CONFIRM_MAC_LEN + 1)))
        assertFalse(verifySasConfirmMac(
            SasConfirmRole.RESPONDER, key, ByteArray(0)))
    }

    @Test fun `MAC is deterministic for a fixed key + role`() {
        val key = ByteArray(32) { 5 }
        val a = buildSasConfirmMac(SasConfirmRole.INITIATOR, key)
        val b = buildSasConfirmMac(SasConfirmRole.INITIATOR, key)
        assertArrayEquals(a, b)
    }

    @Test fun `MAC build rejects too-short keys`() {
        assertThrows(IllegalArgumentException::class.java) {
            buildSasConfirmMac(SasConfirmRole.INITIATOR, ByteArray(15))
        }
    }

    // ─── envelope shape sanity ────────────────────────────────────

    @Test fun `built envelope has the OFFER+SDP shape the broker requires`() {
        val env = buildSasStep1Envelope("dst-id", ByteArray(32)) as JsonObject
        assertEquals("OFFER", (env["type"] as JsonPrimitive).content)
        assertEquals("dst-id", (env["dst"] as JsonPrimitive).content)
        val payload = env["payload"] as JsonObject
        assertNotNull(payload["sdp"], "broker rejects messages without an SDP body")
        assertEquals("data", (payload["type"] as JsonPrimitive).content)
        val md = payload["metadata"] as JsonObject
        assertEquals(PROTOCOL_VERSION.toString(), (md["v"] as JsonPrimitive).content)
        assertEquals(SAS_STEP_1, (md["kind"] as JsonPrimitive).content)
    }

    // ─── helpers ──────────────────────────────────────────────────

    private fun withSrc(envelope: kotlinx.serialization.json.JsonElement, src: String):
        kotlinx.serialization.json.JsonElement {
        // The broker injects `src` on inbound delivery; tests need to
        // simulate that on the receive path. build-side envelopes
        // don't carry src (it's the sender's identity, not its own).
        val obj = envelope as JsonObject
        return buildJsonObject {
            obj.entries.forEach { (k, v) -> put(k, v) }
            put("src", src)
        }
    }

    /** Replace `payload.metadata` via [transform], preserving the
     * rest of the envelope shape. */
    private fun mutateMetadata(
        env: JsonObject,
        transform: (JsonObject) -> JsonObject,
    ): JsonObject {
        val payload = env["payload"] as JsonObject
        val md = payload["metadata"] as JsonObject
        val newMd = transform(md)
        return buildJsonObject {
            env.entries.forEach { (k, v) ->
                if (k != "payload") put(k, v) else putJsonObject("payload") {
                    payload.entries.forEach { (pk, pv) ->
                        if (pk != "metadata") put(pk, pv)
                    }
                    put("metadata", newMd)
                }
            }
        }
    }
}
