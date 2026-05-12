package com.gutschke.wgrtc.signalling

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import java.util.Base64
import java.util.concurrent.atomic.AtomicReference

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OfferSenderTest {

    @BeforeAll fun installJvmSodium() {
        Sodium.setForTest(LazySodiumJava(SodiumJava()))
    }
    @AfterAll fun restoreSodium() { Sodium.setForTest(null) }

    private val sigboxKey = ByteArray(32) { 0x55.toByte() }
    private val dstRoutingId = "deadbeef".repeat(8)

    @Test fun `sendWake builds a kind=signal_wake OFFER addressed to dst and passes it to sendVia`() = runBlocking {
        val captured = AtomicReference<String?>(null)
        val ok = OfferSender().sendWake(
            sendVia = { env -> captured.set(env); true },
            sigboxKey = sigboxKey,
            dstRoutingId = dstRoutingId,
        )
        assertTrue(ok, "sendWake reported failure")
        val frame = captured.get()
        assertNotNull(frame, "sendVia was never called")
        val obj = Json.parseToJsonElement(frame!!) as JsonObject
        assertEquals("OFFER", (obj["type"] as JsonPrimitive).content)
        assertEquals(dstRoutingId, (obj["dst"] as JsonPrimitive).content)
        val md = (obj["payload"] as JsonObject)["metadata"] as JsonObject
        assertEquals("signal_wake", (md["kind"] as JsonPrimitive).content)
    }

    @Test fun `sendWake's blob decrypts to an empty candidates list`() = runBlocking {
        val captured = AtomicReference<String?>(null)
        OfferSender().sendWake(
            sendVia = { env -> captured.set(env); true },
            sigboxKey = sigboxKey,
            dstRoutingId = dstRoutingId,
        )
        val frame = captured.get()!!
        val md = ((Json.parseToJsonElement(frame) as JsonObject)["payload"]
                  as JsonObject)["metadata"] as JsonObject
        val blob = (md["blob"] as JsonPrimitive).content
        // Decrypt with the same key.
        val ct = Base64.getDecoder().decode(blob)
        val plain = secretboxDecrypt(ct, sigboxKey)
        assertNotNull(plain, "blob did not decrypt with the sigbox key")
        val plaintext = Json.parseToJsonElement(plain!!.toString(Charsets.UTF_8)) as JsonObject
        assertEquals(PROTOCOL_VERSION,
            (plaintext["v"] as JsonPrimitive).content.toInt())
        // The wake's candidates MUST be an empty list — the sender is
        // explicitly NOT claiming an endpoint.
        val cands = plaintext["candidates"] as JsonArray
        assertTrue(cands.isEmpty(), "expected empty candidates list, got $cands")
    }

    @Test fun `sendWake propagates sendVia failure as false`() = runBlocking {
        val ok = OfferSender().sendWake(
            sendVia = { _ -> false },
            sigboxKey = sigboxKey,
            dstRoutingId = dstRoutingId,
        )
        assertFalse(ok)
    }

    @Test fun `sendWake calls sendVia exactly once`() = runBlocking {
        var calls = 0
        OfferSender().sendWake(
            sendVia = { _ -> calls += 1; true },
            sigboxKey = sigboxKey,
            dstRoutingId = dstRoutingId,
        )
        assertEquals(1, calls)
    }
}
