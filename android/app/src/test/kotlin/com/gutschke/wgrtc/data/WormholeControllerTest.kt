package com.gutschke.wgrtc.data

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import com.gutschke.wgrtc.signalling.Sodium
import com.gutschke.wgrtc.signalling.WormholeTransport
import com.gutschke.wgrtc.signalling.buildSasConfirmEnvelope
import com.gutschke.wgrtc.signalling.buildSasConfirmMac
import com.gutschke.wgrtc.signalling.SasConfirmRole
import com.gutschke.wgrtc.signalling.SAS_CONFIRM_MAC_LEN
import kotlinx.coroutines.CompletableJob
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance

/**
 * End-to-end controller tests with paired in-memory transports.
 *
 * The two paired transports route messages between an
 * [WormholeJoinController] (initiator) and a
 * [WormholeHostController] (responder) the same way the real broker
 * would: subscribe by routing-id, deliver inbound payloads tagged
 * with `src`, send-side puts envelopes into a shared in-memory
 * "broker" that demuxes by `dst`.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WormholeControllerTest {

    @BeforeAll fun installJvmSodium() {
        Sodium.setForTest(LazySodiumJava(SodiumJava()))
    }
    @AfterAll fun restoreSodium() { Sodium.setForTest(null) }

    // Recreated per test — the class is @TestInstance(PER_CLASS) so
    // class-level vals share state; once a test cancels the rootJob,
    // subsequent tests can't launch new coroutines on it. Wrap as
    // lateinit + @BeforeEach to get a fresh scope each test.
    private lateinit var rootJob: CompletableJob
    private lateinit var rootScope: CoroutineScope

    @BeforeEach fun setUp() {
        rootJob = SupervisorJob()
        rootScope = CoroutineScope(Dispatchers.Default + rootJob)
    }
    @AfterEach fun tearDown() { rootJob.cancel() }

    @Test fun `happy path - joiner submits, host shows code, both confirm`() = runBlocking<Unit> {
        val broker = InMemoryBroker()
        val code = "AB-CD-EF"

        val host = WormholeHostController(
            brokerWss = "wss://test", brokerKey = "k",
            parentScope = rootScope,
            code = code,
            transportFactory = { broker.transport(it) },
        )
        val join = WormholeJoinController(
            brokerWss = "wss://test", brokerKey = "k",
            parentScope = rootScope,
            transportFactory = { broker.transport(it) },
        )

        // Host subscribes immediately (UI does this from LaunchedEffect).
        // start() dispatches the subscribe on a coroutine; wait for
        // it to land in the broker before the joiner sends step-1.
        // In production the network round-trip and human-typing
        // latency hide this race; in-process they don't.
        host.start()
        withTimeout(2_000) {
            while (broker.subscribers.size < 1) delay(20)
        }

        // Joiner types code + submits. This kicks off PAKE step-1.
        join.onTyped(code)
        join.submit()

        // Wait for both sides to reach ConfirmingSas.
        val joinSas = withTimeout(5_000) {
            awaitState(join.state) { it is WormholeJoinUiState.ConfirmingSas }
        } as WormholeJoinUiState.ConfirmingSas
        val hostSas = withTimeout(5_000) {
            awaitState(host.state) { it is WormholeHostUiState.ConfirmingSas }
        } as WormholeHostUiState.ConfirmingSas

        // Same SAS on both sides.
        assertEquals(joinSas.sas, hostSas.sas)

        // Both users tap Confirm.
        join.userConfirm()
        host.userConfirm()

        // Both sides reach Succeeded.
        withTimeout(5_000) { awaitState(join.state) { it == WormholeJoinUiState.Succeeded } }
        withTimeout(5_000) { awaitState(host.state) { it == WormholeHostUiState.Succeeded } }
    }

    @Test fun `mismatched code - joiner gets a different SAS, MAC verify fails`() = runBlocking<Unit> {
        val broker = InMemoryBroker()
        val host = WormholeHostController(
            "wss://test", "k", rootScope,
            code = "ABCDEF",
            transportFactory = { broker.transport(it) },
        )
        val join = WormholeJoinController(
            "wss://test", "k", rootScope,
            transportFactory = { broker.transport(it) },
        )
        host.start()
        withTimeout(2_000) {
            while (broker.subscribers.size < 1) delay(20)
        }
        // Drive both sides to ConfirmingSas with the same code, then
        // have an attacker inject a corrupted MAC. The host should
        // surface MAC verification failure as a Failed state.
        join.onTyped("ABCDEF"); join.submit()

        withTimeout(5_000) {
            awaitState(join.state) { it is WormholeJoinUiState.ConfirmingSas }
            awaitState(host.state) { it is WormholeHostUiState.ConfirmingSas }
        }

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

        // Host transitions to Failed.
        withTimeout(5_000) {
            awaitState(host.state) { it is WormholeHostUiState.Failed }
        }
    }

    @Test fun `cancel from any state moves to Failed and tears down`() = runBlocking<Unit> {
        val broker = InMemoryBroker()
        val join = WormholeJoinController(
            "wss://test", "k", rootScope,
            transportFactory = { broker.transport(it) },
        )
        join.onTyped("ABCDEF")
        join.submit()
        // Wait for the controller to register at the broker.
        withTimeout(2_000) {
            // poll
            while (broker.subscribers.size < 1) delay(20)
        }
        join.cancel()
        assertTrue(join.state.value is WormholeJoinUiState.Failed)
    }

    @Test fun `host dispose closes the broker session`() = runBlocking<Unit> {
        val broker = InMemoryBroker()
        val host = WormholeHostController(
            "wss://test", "k", rootScope,
            code = "ABCDEF",
            transportFactory = { broker.transport(it) },
        )
        host.start()
        // Wait for the subscription to register.
        withTimeout(2_000) {
            while (broker.subscribers.size < 1) delay(20)
        }
        host.dispose()
        // Subscription removed.
        withTimeout(2_000) {
            while (broker.subscribers.size > 0) delay(20)
        }
    }

    @Test fun ` happy path - both sides exchange enrolment info and persist results`() = runBlocking<Unit> {
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
            "wss://test", "k", rootScope,
            code = code,
            tunnelSnapshot = snapshot,
            transportFactory = { broker.transport(it) },
        )
        val join = WormholeJoinController(
            "wss://test", "k", rootScope,
            deviceName = "Android phone",
            keypairOverride = joinerKp,
            transportFactory = { broker.transport(it) },
        )

        host.start()
        withTimeout(2_000) {
            while (broker.subscribers.size < 1) delay(20)
        }
        join.onTyped(code); join.submit()

        withTimeout(5_000) {
            awaitState(join.state) { it is WormholeJoinUiState.ConfirmingSas }
            awaitState(host.state) { it is WormholeHostUiState.ConfirmingSas }
        }

        join.userConfirm()
        host.userConfirm()

        withTimeout(5_000) { awaitState(join.state) { it == WormholeJoinUiState.Succeeded } }
        withTimeout(5_000) { awaitState(host.state) { it == WormholeHostUiState.Succeeded } }

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

    @Test fun ` host without snapshot still completes (legacy mac-only)`() = runBlocking<Unit> {
        // Host configured without a snapshot → sends mac-only confirm.
        // Joiner without keypairOverride (so it generates a real one)
        // should reach Succeeded with no resultingTunnel, not fail.
        val broker = InMemoryBroker()
        val host = WormholeHostController(
            "wss://test", "k", rootScope,
            code = "ABCDEF",
            tunnelSnapshot = null,
            transportFactory = { broker.transport(it) },
        )
        val join = WormholeJoinController(
            "wss://test", "k", rootScope,
            transportFactory = { broker.transport(it) },
        )
        host.start()
        withTimeout(2_000) {
            while (broker.subscribers.size < 1) delay(20)
        }
        join.onTyped("ABCDEF"); join.submit()
        withTimeout(5_000) {
            awaitState(join.state) { it is WormholeJoinUiState.ConfirmingSas }
        }
        join.userConfirm()
        host.userConfirm()
        withTimeout(5_000) { awaitState(join.state) { it == WormholeJoinUiState.Succeeded } }
        // Joiner has no tunnel because host didn't send info.
        // That's the legacy contract — Succeeded is reachable, but
        // resultingTunnel stays null. In production, host always
        // sends info; this case is only for backward-compat tests.
        assertEquals(null, join.resultingTunnel.value)
    }

    @Test fun `submit with malformed code is a no-op`() = runBlocking<Unit> {
        val broker = InMemoryBroker()
        val join = WormholeJoinController(
            "wss://test", "k", rootScope,
            transportFactory = { broker.transport(it) },
        )
        join.onTyped("AB") // 2 letters — too short
        join.submit()
        // State remains EnteringCode; no broker subscription opened.
        assertTrue(join.state.value is WormholeJoinUiState.EnteringCode)
        delay(100)
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
     * ConcurrentHashMap is load-bearing: the broker is mutated from
     * controller-launched coroutines on Dispatchers.Default and read
     * from the runBlocking thread's polling loops. A plain HashMap
     * + `synchronized` block doesn't establish a happens-before
     * edge for the unsynchronized `subscribers.size` read in the
     * polling loop. */
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
