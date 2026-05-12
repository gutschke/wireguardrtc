package com.gutschke.wgrtc.data

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import com.gutschke.wgrtc.signalling.PROTOCOL_VERSION
import com.gutschke.wgrtc.signalling.SignalWakeSender
import com.gutschke.wgrtc.signalling.Sodium
import com.gutschke.wgrtc.signalling.deriveSigboxKey
import com.gutschke.wgrtc.signalling.pubKeyFromPrivate
import com.gutschke.wgrtc.signalling.routingId
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Unit tests for [ListenerHub.wake] — the per-tunnel client-initiated
 * wake. We do NOT spin a MockWebServer here; that's covered in
 * `OfferSenderTest`. These tests verify ListenerHub correctly:
 *
 * - looks up the tunnel by id
 * - derives matching crypto materials (sigbox key, our pubkey, salt)
 * - computes dst routing-id = SHA256(server_pub_b64 || salt)
 * - debounces back-to-back calls
 * - returns silently for missing / non-ENROLL / malformed tunnels
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ListenerHubWakeTest {

    @BeforeAll fun installJvmSodium() {
        Sodium.setForTest(LazySodiumJava(SodiumJava()))
    }
    @AfterAll fun restoreSodium() { Sodium.setForTest(null) }

    /** Test double: records each invocation; never blocks. */
    private class FakeSender : SignalWakeSender {
        data class Call(
            val sigboxKey: ByteArray,
            val dstRoutingId: String,
        )
        val calls = ConcurrentLinkedQueue<Call>()
        var resultSupplier: () -> Boolean = { true }
        override suspend fun sendWake(
            sendVia: suspend (String) -> Boolean,
            sigboxKey: ByteArray,
            dstRoutingId: String,
        ): Boolean {
            calls += Call(sigboxKey, dstRoutingId)
            return resultSupplier()
        }
    }

    private val rng = SecureRandom()

    private fun makeStore(dir: Path) =
        TunnelStore(File(dir.toFile(), "tunnels.json"))

    /** Build a fully-populated ENROLL-source tunnel with valid X25519
     * keypair so deriveSigboxKey succeeds. */
    private fun freshEnrollTunnel(id: String = "t1"): Tunnel {
        val priv = ByteArray(32).also { rng.nextBytes(it) }
        val serverPriv = ByteArray(32).also { rng.nextBytes(it) }
        val serverPub = pubKeyFromPrivate(serverPriv)
        val privB64 = Base64.getEncoder().encodeToString(priv)
        val serverPubB64 = Base64.getEncoder().encodeToString(serverPub)
        val cfg = """
            [Interface]
            PrivateKey = $privB64
            Address = 10.7.0.42/32
            [Peer]
            PublicKey = $serverPubB64
            Endpoint = 192.0.2.1:51820
            AllowedIPs = 0.0.0.0/0
        """.trimIndent()
        // saltB64 is URL-safe base64, no padding (per Tunnel.kt). 16
        // random bytes → 22 base64 chars, no `=`.
        val rawSalt = ByteArray(16).also { rng.nextBytes(it) }
        val saltB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(rawSalt)
        return Tunnel(
            id = id, name = "test", configText = cfg,
            source = Tunnel.Source.ENROLL,
            brokerWss = "wss://broker.example.com/peerjs",
            brokerKey = "key-$id",
            saltB64 = saltB64,
        )
    }

    /** The ts source the hub will see; controlled by the test. */
    private class Clock(start: Long = 100_000L) {
        @Volatile var nowMs: Long = start
        val getter: () -> Long = { nowMs }
    }

    /** Hub spawns coroutines on Dispatchers.IO; flush by polling. */
    private fun awaitTrue(timeoutMs: Long = 2_000, predicate: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (!predicate() && System.currentTimeMillis() < deadline) {
            Thread.sleep(10)
        }
        assertTrue(predicate(), "predicate never satisfied")
    }

    // ─── tests ────────────────────────────────────────────────────────

    @Test fun `wake on unknown tunnel id is a no-op`(@TempDir dir: Path) {
        val store = makeStore(dir)
        val sender = FakeSender()
        val hub = ListenerHub(store, sender, Clock().getter)
        hub.wake("does-not-exist")
        // Give the dispatcher a chance to do nothing.
        Thread.sleep(50)
        assertTrue(sender.calls.isEmpty(), "expected no sendWake; got ${sender.calls}")
    }

    @Test fun `wake on non-ENROLL tunnel does not fire`(@TempDir dir: Path) {
        val store = makeStore(dir)
        store.save(listOf(Tunnel(
            id = "leg", name = "legacy",
            configText = "[Interface]\nPrivateKey=AAA\n",
            source = Tunnel.Source.LEGACY,
        )))
        val sender = FakeSender()
        val hub = ListenerHub(store, sender, Clock().getter)
        hub.wake("leg")
        Thread.sleep(50)
        assertTrue(sender.calls.isEmpty())
    }

    @Test fun `wake on ENROLL tunnel fires sendWake with the right routing-id`(
        @TempDir dir: Path,
    ) = runBlocking {
        val store = makeStore(dir)
        val tunnel = freshEnrollTunnel()
        store.save(listOf(tunnel))
        val sender = FakeSender()
        val hub = ListenerHub(store, sender, Clock().getter)
        hub.wake(tunnel.id)
        awaitTrue { sender.calls.isNotEmpty() }
        val call = sender.calls.peek()!!
        // dstRoutingId = SHA256(server_pub_b64 || salt_bytes_decoded)
        val pad = when (tunnel.saltB64!!.length % 4) { 2->"=="; 3->"="; else->"" }
        val saltBytes = Base64.getUrlDecoder().decode(tunnel.saltB64 + pad)
        val expectedServerPub = tunnel.configText.lineSequence()
            .first { it.trim().startsWith("PublicKey") }
            .substringAfter("=").trim()
        assertEquals(routingId(expectedServerPub, saltBytes), call.dstRoutingId)
        // sigboxKey is 32 bytes (BLAKE2b32 output).
        assertEquals(32, call.sigboxKey.size)
    }

    @Test fun `wake debounces back-to-back calls`(@TempDir dir: Path) = runBlocking {
        val store = makeStore(dir)
        val tunnel = freshEnrollTunnel()
        store.save(listOf(tunnel))
        val sender = FakeSender()
        val clock = Clock()
        val hub = ListenerHub(store, sender, clock.getter)

        hub.wake(tunnel.id)
        awaitTrue { sender.calls.size == 1 }

        // Immediate second + third call within debounce window: dropped.
        clock.nowMs += 100
        hub.wake(tunnel.id)
        clock.nowMs += 500
        hub.wake(tunnel.id)
        Thread.sleep(50)
        assertEquals(1, sender.calls.size, "expected debounce; got ${sender.calls.size}")

        // Advance past WAKE_DEBOUNCE_MS (3 s) and try again.
        clock.nowMs += 3_500
        hub.wake(tunnel.id)
        awaitTrue { sender.calls.size == 2 }
    }

    @Test fun `debounce is per-tunnel, not global`(@TempDir dir: Path) = runBlocking {
        val store = makeStore(dir)
        val a = freshEnrollTunnel("a")
        val b = freshEnrollTunnel("b")
        store.save(listOf(a, b))
        val sender = FakeSender()
        val hub = ListenerHub(store, sender, Clock().getter)
        hub.wake("a")
        hub.wake("b")
        awaitTrue { sender.calls.size == 2 }
        // Each tunnel produces a distinct dstRoutingId (different
        // server pub + different salt → different SHA256).
        val dsts = sender.calls.map { it.dstRoutingId }.toSet()
        assertEquals(2, dsts.size, "expected two distinct dstRoutingIds, got $dsts")
    }

    @Test fun `wake on tunnel with corrupt PrivateKey is a no-op`(
        @TempDir dir: Path,
    ) = runBlocking {
        val store = makeStore(dir)
        val good = freshEnrollTunnel()
        // Mangle the PrivateKey line so base64 decode fails.
        val broken = good.copy(
            configText = good.configText.replace(Regex("PrivateKey = .+"),
                "PrivateKey = !!!not-valid-base64"))
        store.save(listOf(broken))
        val sender = FakeSender()
        val hub = ListenerHub(store, sender, Clock().getter)
        hub.wake(broken.id)
        Thread.sleep(50)
        assertTrue(sender.calls.isEmpty())
    }

    @Test fun `unused PROTOCOL_VERSION import sentinel`() {
        // Keep the import live so compile failures from a stale
        // signalling::PROTOCOL_VERSION rename surface here.
        assertTrue(PROTOCOL_VERSION >= 1)
    }
}
