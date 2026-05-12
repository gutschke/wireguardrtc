package com.gutschke.wgrtc.signalling

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import kotlinx.serialization.json.put
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance

/**
 * End-to-end check: a full wormhole-code session simulated in-process
 * through every layer of . Verifies the pieces compose
 * correctly — SPAKE2 messages flow through the wire-format envelopes,
 * both sides arrive at the same SPAKE2 key, the SAS derivation
 * yields the same words on both sides, and the confirm-MAC round-
 * trips through [buildSasConfirmEnvelope] / [extractSasConfirm].
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SasFlowTest {

    @BeforeAll fun installJvmSodium() {
        Sodium.setForTest(LazySodiumJava(SodiumJava()))
    }
    @AfterAll fun restoreSodium() { Sodium.setForTest(null) }

    @Test fun `happy path - matching code yields matching SAS and MAC accept`() {
        val code = "amber-pixel-7".toByteArray()
        val initRouting = sasRoutingIdInitiator(code)
        val respRouting = sasRoutingIdResponder(code)
        assertNotEquals(initRouting, respRouting)

        // 1. Initiator computes its SPAKE2 message and sends it.
        val initiator = Spake2(Spake2.Role.ALICE, code)
        val msgI = initiator.start()
        val step1Outbound = buildSasStep1Envelope(respRouting, msgI)

        // The broker delivers the envelope with `src` set to the
        // initiator's routing id. Simulate that:
        val step1Inbound = injectSrc(step1Outbound, initRouting)
        val parsed1 = extractSasStep1(step1Inbound)!!
        assertEquals(initRouting, parsed1.src)

        // 2. Responder reads the message, computes its own, replies.
        val responder = Spake2(Spake2.Role.BOB, code)
        val msgR = responder.start()
        val step2Outbound = buildSasStep2Envelope(initRouting, msgR)
        val step2Inbound = injectSrc(step2Outbound, respRouting)
        val parsed2 = extractSasStep2(step2Inbound)!!
        assertEquals(respRouting, parsed2.src)

        // 3. Each side completes finish() and gets the same key.
        val keyI = initiator.finish(parsed2.pakeMsg)
        val keyR = responder.finish(parsed1.pakeMsg)
        assertArrayEquals(keyI, keyR)

        // 4. Both sides derive the SAS independently — same words.
        val sasI = deriveSas(keyI)
        val sasR = deriveSas(keyR)
        assertEquals(sasI, sasR)

        // 5. After the user confirms the SAS matches, both sides
        // exchange role-MACs and verify each other.
        val initSentMac = buildSasConfirmMac(SasConfirmRole.INITIATOR, keyI)
        val respSentMac = buildSasConfirmMac(SasConfirmRole.RESPONDER, keyR)

        val initConfirmEnv = injectSrc(
            buildSasConfirmEnvelope(respRouting, initSentMac), initRouting)
        val respConfirmEnv = injectSrc(
            buildSasConfirmEnvelope(initRouting, respSentMac), respRouting)

        // Responder receives initiator's MAC → verifies as INITIATOR role.
        val respView = extractSasConfirm(initConfirmEnv)!!
        assertTrue(verifySasConfirmMac(SasConfirmRole.INITIATOR, keyR, respView.mac))

        // Initiator receives responder's MAC → verifies as RESPONDER role.
        val initView = extractSasConfirm(respConfirmEnv)!!
        assertTrue(verifySasConfirmMac(SasConfirmRole.RESPONDER, keyI, initView.mac))
    }

    @Test fun `mismatched code - SAS differs and MAC verify fails`() {
        // Threat model: an attacker who relays one half of the
        // SPAKE2 exchange but not the other ends up with a *different*
        // shared key on each side. SAS catches this on human
        // confirmation; the MAC catches it on the protocol level.
        val initiator = Spake2(Spake2.Role.ALICE, "alpha".toByteArray())
        val responder = Spake2(Spake2.Role.BOB, "beta".toByteArray())
        val msgI = initiator.start()
        val msgR = responder.start()
        val keyI = initiator.finish(msgR)
        val keyR = responder.finish(msgI)

        // Different keys.
        assertFalse(keyI.contentEquals(keyR))

        // SAS will differ — humans see the mismatch on screen.
        val sasI = deriveSas(keyI)
        val sasR = deriveSas(keyR)
        assertNotEquals(sasI, sasR)

        // Even if the user blindly clicks "Confirm" the MAC step
        // catches it: initiator's MAC under keyI doesn't verify
        // under keyR.
        val initMac = buildSasConfirmMac(SasConfirmRole.INITIATOR, keyI)
        assertFalse(verifySasConfirmMac(SasConfirmRole.INITIATOR, keyR, initMac))
    }

    /** Simulate the broker injecting `src` on delivery. */
    private fun injectSrc(
        envelope: kotlinx.serialization.json.JsonElement,
        src: String,
    ): kotlinx.serialization.json.JsonElement {
        val obj = envelope as kotlinx.serialization.json.JsonObject
        return kotlinx.serialization.json.buildJsonObject {
            obj.entries.forEach { (k, v) -> put(k, v) }
            put("src", src)
        }
    }
}
