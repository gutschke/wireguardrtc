package com.gutschke.wgrtc.signalling

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WormholeBrokerSessionTest {

    @BeforeAll fun installJvmSodium() {
        Sodium.setForTest(LazySodiumJava(SodiumJava()))
    }
    @AfterAll fun restoreSodium() { Sodium.setForTest(null) }

    private fun code() = "moose-pixel-7".toByteArray()

    // ─── routing-id wiring ─────────────────────────────────────────

    @Test fun `initiator subscribes under init id and sends to resp id`() = runBlocking {
        val transport = FakeTransport()
        val s = WormholeBrokerSession(SasConfirmRole.INITIATOR, code(), transport)
        assertEquals(sasRoutingIdInitiator(code()), s.ourRoutingId)
        assertEquals(sasRoutingIdResponder(code()), s.peerRoutingId)
        s.start { /* not exercised here */ }
        assertEquals(sasRoutingIdInitiator(code()), transport.startedRoutingId)
    }

    @Test fun `responder subscribes under resp id and sends to init id`() = runBlocking {
        val transport = FakeTransport()
        val s = WormholeBrokerSession(SasConfirmRole.RESPONDER, code(), transport)
        assertEquals(sasRoutingIdResponder(code()), s.ourRoutingId)
        assertEquals(sasRoutingIdInitiator(code()), s.peerRoutingId)
        s.start { }
        assertEquals(sasRoutingIdResponder(code()), transport.startedRoutingId)
    }

    @Test fun `our and peer ids differ`() {
        val s = WormholeBrokerSession(SasConfirmRole.INITIATOR, code(), FakeTransport())
        assertNotEquals(s.ourRoutingId, s.peerRoutingId)
    }

    // ─── send paths build the right envelope kinds ────────────────

    @Test fun `sendStep1 publishes a sas_step_1 envelope to the peer`() = runBlocking {
        val transport = FakeTransport()
        val s = WormholeBrokerSession(SasConfirmRole.INITIATOR, code(), transport)
        s.start { }
        val pake = ByteArray(32) { 1 }
        assertTrue(s.sendStep1(pake))
        val sent = transport.sent.single() as JsonObject
        assertEquals(s.peerRoutingId, (sent["dst"] as kotlinx.serialization.json.JsonPrimitive).content)
        // Confirm extractSasStep1 round-trips the payload back.
        val withSrc = injectSrc(sent, "anyone")
        val parsed = extractSasStep1(withSrc)!!
        assertArrayEquals(pake, parsed.pakeMsg)
    }

    @Test fun `sendStep2 publishes a sas_step_2 envelope`() = runBlocking {
        val transport = FakeTransport()
        val s = WormholeBrokerSession(SasConfirmRole.RESPONDER, code(), transport)
        s.start { }
        val pake = ByteArray(32) { 2 }
        assertTrue(s.sendStep2(pake))
        val sent = transport.sent.single()
        val parsed = extractSasStep2(injectSrc(sent, "anyone"))!!
        assertArrayEquals(pake, parsed.pakeMsg)
    }

    @Test fun `sendConfirm publishes a sas_confirm envelope`() = runBlocking {
        val transport = FakeTransport()
        val s = WormholeBrokerSession(SasConfirmRole.INITIATOR, code(), transport)
        s.start { }
        val mac = ByteArray(SAS_CONFIRM_MAC_LEN) { 9 }
        assertTrue(s.sendConfirm(mac))
        val sent = transport.sent.single()
        val parsed = extractSasConfirm(injectSrc(sent, "anyone"))!!
        assertArrayEquals(mac, parsed.mac)
    }

    @Test fun `send returns false when the transport refuses`() = runBlocking {
        val transport = FakeTransport(sendOk = false)
        val s = WormholeBrokerSession(SasConfirmRole.INITIATOR, code(), transport)
        s.start { }
        assertFalse(s.sendStep1(ByteArray(32)))
    }

    // ─── inbound demux ────────────────────────────────────────────

    @Test fun `inbound step1 fires SasInbound dot Step1`() = runBlocking {
        val transport = FakeTransport()
        val s = WormholeBrokerSession(SasConfirmRole.RESPONDER, code(), transport)
        val received = mutableListOf<SasInbound>()
        s.start { received += it }

        val msg = injectSrc(buildSasStep1Envelope(s.ourRoutingId, ByteArray(32) { 7 }),
            src = sasRoutingIdInitiator(code()))
        transport.deliver(msg)

        val ev = received.single() as SasInbound.Step1
        assertEquals(sasRoutingIdInitiator(code()), ev.parsed.src)
    }

    @Test fun `inbound step2 fires SasInbound dot Step2`() = runBlocking {
        val transport = FakeTransport()
        val s = WormholeBrokerSession(SasConfirmRole.INITIATOR, code(), transport)
        val received = mutableListOf<SasInbound>()
        s.start { received += it }

        val msg = injectSrc(buildSasStep2Envelope(s.ourRoutingId, ByteArray(32) { 8 }),
            src = sasRoutingIdResponder(code()))
        transport.deliver(msg)

        assertTrue(received.single() is SasInbound.Step2)
    }

    @Test fun `inbound confirm fires SasInbound dot Confirm`() = runBlocking {
        val transport = FakeTransport()
        val s = WormholeBrokerSession(SasConfirmRole.INITIATOR, code(), transport)
        val received = mutableListOf<SasInbound>()
        s.start { received += it }

        val msg = injectSrc(
            buildSasConfirmEnvelope(s.ourRoutingId, ByteArray(SAS_CONFIRM_MAC_LEN) { 1 }),
            src = sasRoutingIdResponder(code()))
        transport.deliver(msg)

        assertTrue(received.single() is SasInbound.Confirm)
    }

    @Test fun `inbound junk is silently dropped`() = runBlocking {
        val transport = FakeTransport()
        val s = WormholeBrokerSession(SasConfirmRole.INITIATOR, code(), transport)
        val received = mutableListOf<SasInbound>()
        s.start { received += it }

        // A non-SAS message — e.g. a stray PeerJS HEARTBEAT.
        transport.deliver(buildJsonObject {
            put("type", "HEARTBEAT")
        })
        // A malformed SAS envelope (wrong version) — extractor returns null.
        val malformed = buildJsonObject {
            put("type", "OFFER")
            put("src", "x")
            put("dst", "y")
            put("payload", buildJsonObject {
                put("metadata", buildJsonObject {
                    put("v", 99) // wrong version
                    put("kind", "sas_step_1")
                })
            })
        }
        transport.deliver(malformed)

        assertTrue(received.isEmpty(),
            "junk + malformed messages must not surface to the listener")
    }

    // ─── lifecycle ────────────────────────────────────────────────

    @Test fun `start a second time throws`() = runBlocking {
        val s = WormholeBrokerSession(SasConfirmRole.INITIATOR, code(), FakeTransport())
        s.start { }
        assertThrows(IllegalStateException::class.java) {
            runBlocking { s.start { } }
        }
    }

    @Test fun `start after close throws`() = runBlocking {
        val s = WormholeBrokerSession(SasConfirmRole.INITIATOR, code(), FakeTransport())
        s.close()
        assertThrows(IllegalStateException::class.java) {
            runBlocking { s.start { } }
        }
    }

    @Test fun `close is idempotent`() = runBlocking {
        val transport = FakeTransport()
        val s = WormholeBrokerSession(SasConfirmRole.INITIATOR, code(), transport)
        s.start { }
        s.close()
        s.close()
        s.close()
        assertEquals(1, transport.closeCount)
    }

    @Test fun `close after start tears down the transport`() = runBlocking {
        val transport = FakeTransport()
        val s = WormholeBrokerSession(SasConfirmRole.INITIATOR, code(), transport)
        s.start { }
        s.close()
        assertEquals(1, transport.closeCount)
    }

    @Test fun `decodeSasInbound returns null for non-SAS message`() {
        val msg = buildJsonObject { put("type", "HEARTBEAT") }
        assertNull(decodeSasInbound(msg))
    }

    // ─── helpers ──────────────────────────────────────────────────

    private fun injectSrc(env: JsonElement, src: String): JsonElement {
        val obj = env as JsonObject
        return buildJsonObject {
            obj.entries.forEach { (k, v) -> put(k, v) }
            put("src", src)
        }
    }

    /** In-memory transport double — captures sends + lets tests
     * inject inbound payloads via [deliver]. */
    private class FakeTransport(
        private val sendOk: Boolean = true,
    ) : WormholeTransport {
        var startedRoutingId: String? = null
        val sent = mutableListOf<JsonElement>()
        var closeCount = 0
        private var inboundHandler: ((JsonElement) -> Unit)? = null

        override suspend fun start(
            routingId: String,
            onInbound: (JsonElement) -> Unit,
        ) {
            startedRoutingId = routingId
            inboundHandler = onInbound
        }
        override fun send(envelope: JsonElement): Boolean {
            if (sendOk) sent += envelope
            return sendOk
        }
        override suspend fun close() { closeCount++ }
        fun deliver(msg: JsonElement) {
            (inboundHandler ?: error("not started")).invoke(msg)
        }
    }
}
