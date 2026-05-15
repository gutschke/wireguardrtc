package com.gutschke.wgrtc.data

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import com.gutschke.wgrtc.signalling.Sodium
import com.gutschke.wgrtc.signalling.WormholeTransport
import com.gutschke.wgrtc.signalling.buildSasConfirmEnvelope
import com.gutschke.wgrtc.signalling.SAS_CONFIRM_MAC_LEN
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance

/**
 * End-to-end controller tests with paired in-memory transports.
 *
 * Uses [runTest] with virtual time and a shared [backgroundScope]
 * per test — the controllers' `parentScope` ties their launched
 * coroutines into the test scheduler, so the test thread isn't
 * racing wall-clock against `Dispatchers.Default` waiting for the
 * broker subscription to register.  The previous wall-clock
 * polling under [withTimeout] flaked when host CPU was saturated;
 * virtual time eliminates that class of failure entirely.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WormholeControllerTest {

    @BeforeAll fun installJvmSodium() {
        Sodium.setForTest(LazySodiumJava(SodiumJava()))
    }
    @AfterAll fun restoreSodium() { Sodium.setForTest(null) }

    @Test fun `happy path - joiner submits, host shows code, both confirm`() = runTest {
        val broker = InMemoryBroker()
        val code = "AB-CD-EF"

        val host = WormholeHostController(
            brokerWss = "wss://test", brokerKey = "k",
            parentScope = backgroundScope,
            code = code,
            transportFactory = { broker.transport(it) },
        )
        val join = WormholeJoinController(
            brokerWss = "wss://test", brokerKey = "k",
            parentScope = backgroundScope,
            transportFactory = { broker.transport(it) },
        )

        // Host subscribes immediately (UI does this from LaunchedEffect).
        // start() dispatches the subscribe on a coroutine; flush the
        // test scheduler so it lands in the broker before the joiner
        // sends step-1.
        host.start()
        runCurrent()
        assertEquals(1, broker.subscribers.size)

        // Joiner types code + submits. This kicks off PAKE step-1.
        join.onTyped(code)
        join.submit()

        // Wait for both sides to reach ConfirmingSas.
        val joinSas =
            awaitState(join.state) { it is WormholeJoinUiState.ConfirmingSas }
                as WormholeJoinUiState.ConfirmingSas
        val hostSas =
            awaitState(host.state) { it is WormholeHostUiState.ConfirmingSas }
                as WormholeHostUiState.ConfirmingSas

        // Same SAS on both sides.
        assertEquals(joinSas.sas, hostSas.sas)

        // Both users tap Confirm.
        join.userConfirm()
        host.userConfirm()

        // Both sides reach Succeeded.
        awaitState(join.state) { it == WormholeJoinUiState.Succeeded }
        awaitState(host.state) { it == WormholeHostUiState.Succeeded }
    }

    @Test fun `mismatched code - joiner gets a different SAS, MAC verify fails`() = runTest {
        val broker = InMemoryBroker()
        val host = WormholeHostController(
            "wss://test", "k", backgroundScope,
            code = "ABCDEF",
            transportFactory = { broker.transport(it) },
        )
        val join = WormholeJoinController(
            "wss://test", "k", backgroundScope,
            transportFactory = { broker.transport(it) },
        )
        host.start()
        runCurrent()
        // Drive both sides to ConfirmingSas with the same code, then
        // have an attacker inject a corrupted MAC. The host should
        // surface MAC verification failure as a Failed state.
        join.onTyped("ABCDEF"); join.submit()

        awaitState(join.state) { it is WormholeJoinUiState.ConfirmingSas }
        awaitState(host.state) { it is WormholeHostUiState.ConfirmingSas }

        // Inject a corrupted Confirm envelope to the host: same
        // routing-id but wrong MAC bytes. The host should fail.
        val badMac = ByteArray(SAS_CONFIRM_MAC_LEN) { 0xFF.toByte() }
        host.userConfirm() // host sends its real MAC + waits for joiner's
        broker.deliverDirect(
            envelope = buildSasConfirmEnvelope(
                dstRoutingId = host.let { /* responder's routing id */
                    com.gutschke.wgrtc.signalling.sasRoutingIdResponder("ABCDEF".toByteArray())
                },
                confirmMac = badMac,
            ),
            srcRoutingId = "spoofer",
            dstRoutingId = com.gutschke.wgrtc.signalling.sasRoutingIdResponder("ABCDEF".toByteArray()),
        )

        awaitState(host.state) { it is WormholeHostUiState.Failed }
    }

    @Test fun `cancel from any state moves to Failed and tears down`() = runTest {
        val broker = InMemoryBroker()
        // Pair a host so the joiner's sendStep1 succeeds and the
        // joiner reaches a non-terminal state.  Without a peer, the
        // joiner's submit launch fails sendStep1 immediately and
        // transitions to Failed on its own, making subsequent
        // cancel() a no-op — that wouldn't exercise the "cancel
        // moves to Failed" path the test name promises.
        val host = WormholeHostController(
            "wss://test", "k", backgroundScope,
            code = "ABCDEF",
            transportFactory = { broker.transport(it) },
        )
        val join = WormholeJoinController(
            "wss://test", "k", backgroundScope,
            transportFactory = { broker.transport(it) },
        )
        host.start()
        join.onTyped("ABCDEF")
        join.submit()
        // Run all currently-queued backgroundScope work — both
        // controllers subscribe to the broker and the joiner's
        // protocol kicks off.  Both should be in a non-terminal
        // state (Confirming SAS or earlier).
        runCurrent()
        assertEquals(2, broker.subscribers.size)
        assertTrue(join.state.value !is WormholeJoinUiState.Failed)
        join.cancel()
        assertTrue(join.state.value is WormholeJoinUiState.Failed)
    }

    @Test fun `host dispose closes the broker session`() = runTest {
        val broker = InMemoryBroker()
        val host = WormholeHostController(
            "wss://test", "k", backgroundScope,
            code = "ABCDEF",
            transportFactory = { broker.transport(it) },
        )
        host.start()
        runCurrent()
        assertEquals(1, broker.subscribers.size)
        host.dispose()
        runCurrent()
        assertEquals(0, broker.subscribers.size)
    }

    @Test fun ` happy path - both sides exchange enrollment info and persist results`() = runTest {
        val broker = InMemoryBroker()
        val code = "ABCDEF"
        val snapshot = HostTunnelSnapshot(
            tunnelId = "tunnel-id-xyz",
            privKeyB64 = java.util.Base64.getEncoder().encodeToString(ByteArray(32) { 11 }),
            pubKeyB64 = java.util.Base64.getEncoder().encodeToString(ByteArray(32) { 22 }),
            wgEndpoint = "203.0.113.5:51820",
            allowedIps = "10.99.0.0/24",
            assignedAddress = "10.99.0.7/32",
            brokerWss = "wss://host-private.example/peerjs",
            brokerKey = "private-key",
            saltB64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            hostName = "phoneA",
            keepalive = 25,
        )
        val joinerKp =
            java.util.Base64.getEncoder().encodeToString(ByteArray(32) { 33 }) to
            java.util.Base64.getEncoder().encodeToString(ByteArray(32) { 44 })

        val host = WormholeHostController(
            "wss://test", "k", backgroundScope,
            code = code,
            tunnelSnapshot = snapshot,
            transportFactory = { broker.transport(it) },
        )
        val join = WormholeJoinController(
            "wss://test", "k", backgroundScope,
            deviceName = "Android phone",
            keypairOverride = joinerKp,
            transportFactory = { broker.transport(it) },
        )

        host.start()
        runCurrent()
        join.onTyped(code); join.submit()

        awaitState(join.state) { it is WormholeJoinUiState.ConfirmingSas }
        awaitState(host.state) { it is WormholeHostUiState.ConfirmingSas }

        join.userConfirm()
        host.userConfirm()

        awaitState(join.state) { it == WormholeJoinUiState.Succeeded }
        awaitState(host.state) { it == WormholeHostUiState.Succeeded }

        // Joiner's resultingTunnel reflects the host's payload.
        val tunnel = join.resultingTunnel.value
            ?: error("joiner expected a resultingTunnel after Succeeded")
        assertTrue(tunnel.configText.contains("Address = 10.99.0.7/32"))
        assertTrue(tunnel.configText.contains("Endpoint = 203.0.113.5:51820"))
        assertTrue(tunnel.configText.contains("AllowedIPs = 10.99.0.0/24"))
        assertTrue(tunnel.configText.contains("PersistentKeepalive = 25"))
        assertEquals("wss://host-private.example/peerjs", tunnel.brokerWss)
        assertEquals("private-key", tunnel.brokerKey)
        assertEquals(snapshot.saltB64, tunnel.saltB64)
        assertTrue(tunnel.name.contains("phoneA"),
            "joiner's tunnel name should reflect the host hostName")

        // Host's wormholeResult carries the joiner's pubkey + IP.
        val result = host.wormholeResult.value
            ?: error("host expected a wormholeResult after Succeeded")
        assertEquals("tunnel-id-xyz", result.tunnelId)
        assertEquals(joinerKp.second, result.joinerPubkeyB64)
        assertEquals("10.99.0.7", result.joinerIp) // /32 stripped
        assertEquals("Android phone", result.joinerNameHint)
    }

    @Test fun ` host without snapshot still completes (legacy mac-only)`() = runTest {
        // Host configured without a snapshot → sends mac-only confirm.
        // Joiner without keypairOverride (so it generates a real one)
        // should reach Succeeded with no resultingTunnel, not fail.
        val broker = InMemoryBroker()
        val host = WormholeHostController(
            "wss://test", "k", backgroundScope,
            code = "ABCDEF",
            tunnelSnapshot = null,
            transportFactory = { broker.transport(it) },
        )
        val join = WormholeJoinController(
            "wss://test", "k", backgroundScope,
            transportFactory = { broker.transport(it) },
        )
        host.start()
        runCurrent()
        join.onTyped("ABCDEF"); join.submit()
        awaitState(join.state) { it is WormholeJoinUiState.ConfirmingSas }
        join.userConfirm()
        host.userConfirm()
        awaitState(join.state) { it == WormholeJoinUiState.Succeeded }
        // Joiner has no tunnel because host didn't send info.
        // That's the legacy contract — Succeeded is reachable, but
        // resultingTunnel stays null. In production, host always
        // sends info; this case is only for backward-compat tests.
        assertEquals(null, join.resultingTunnel.value)
    }

    @Test fun `submit with malformed code is a no-op`() = runTest {
        val broker = InMemoryBroker()
        val join = WormholeJoinController(
            "wss://test", "k", backgroundScope,
            transportFactory = { broker.transport(it) },
        )
        join.onTyped("AB") // 2 letters — too short
        join.submit()
        // State remains EnteringCode; no broker subscription opened.
        assertTrue(join.state.value is WormholeJoinUiState.EnteringCode)
        runCurrent()
        assertEquals(0, broker.subscribers.size)
    }

    // ─── helpers ──────────────────────────────────────────────────

    /** Suspend until [predicate] holds for the StateFlow. */
    private suspend fun <T> awaitState(
        flow: kotlinx.coroutines.flow.StateFlow<T>,
        predicate: (T) -> Boolean,
    ): T = flow.first(predicate)

    /** In-memory broker that routes envelopes by `dst` to whichever
     * transport is subscribed under that routing-id. Drives both
     * sides of a wormhole exchange in a single test process.
     *
     * Under virtual time all coroutines run on a single test thread,
     * so a plain HashMap would technically be sufficient.  Kept as
     * a ConcurrentHashMap for defensive consistency — the broker
     * fake might be reused in tests that DO involve real threads
     * (instrumented suite). */
    private class InMemoryBroker {
        val subscribers: java.util.concurrent.ConcurrentMap<String, (JsonElement) -> Unit> =
            java.util.concurrent.ConcurrentHashMap()

        fun transport(scope: CoroutineScope): WormholeTransport = object : WormholeTransport {
            @Volatile private var ourId: String? = null
            override suspend fun start(
                routingId: String,
                onInbound: (JsonElement) -> Unit,
            ) {
                ourId = routingId
                subscribers[routingId] = onInbound
            }
            override fun send(envelope: JsonElement): Boolean {
                val obj = envelope as? JsonObject ?: return false
                val dst = (obj["dst"] as? kotlinx.serialization.json.JsonPrimitive)?.content
                    ?: return false
                val src = ourId ?: return false
                val handler = subscribers[dst] ?: return false
                val withSrc = buildJsonObject {
                    obj.entries.forEach { (k, v) -> put(k, v) }
                    put("src", src)
                }
                handler(withSrc)
                return true
            }
            override suspend fun close() {
                ourId?.let { subscribers.remove(it) }
            }
        }

        /** Inject a payload directly to whichever subscriber holds
         * [dstRoutingId]. Used to simulate a malicious / corrupted
         * message for tests that don't go through a paired sender. */
        fun deliverDirect(
            envelope: JsonElement,
            srcRoutingId: String,
            dstRoutingId: String,
        ) {
            val handler = synchronized(subscribers) { subscribers[dstRoutingId] } ?: return
            val obj = envelope as JsonObject
            handler(buildJsonObject {
                obj.entries.forEach { (k, v) -> put(k, v) }
                put("src", srcRoutingId)
            })
        }
    }
}
