package com.gutschke.wgrtc.signalling

import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Tests for [RoamController], the half of the roam-handling story that
 * decides — given a network-change signal — whether to kick the live
 * tunnel's [ConnectionRunner] into a re-race. The other half (the
 * Android [NetworkChangeMonitor] that fires the signal) is exercised
 * end-to-end on a real device; this suite covers the decision and
 * debounce logic in pure Kotlin so emulator + sandbox tests stay
 * lightweight and deterministic.
 */
class RoamControllerTest {

    private fun ep(ip: String, port: Int = 51820, ts: Long = 1L) =
        EndpointUpdate(ip = ip, port = port, ts = ts)

    /** Minimal scripted controller. Drives `latestHandshakeMs` from a
     * unit-test clock, records every `setEndpoint` call, and counts
     * `bringDown`. */
    private class ScriptController(
        initialHandshakeMs: Long = 0L,
    ) : TunnelEndpointController {
        val setEndpointCalls = mutableListOf<EndpointUpdate>()
        val bringDownCalls = AtomicInteger(0)
        private val handshakeMs = AtomicLong(initialHandshakeMs)

        fun setHandshakeMs(value: Long) { handshakeMs.set(value) }

        // Optional: simulate handshake completion `delayMs` after every
        // setEndpoint call. When non-null, the ScriptController itself
        // bumps `handshakeMs` to a fresh value after the delay so the
        // race's `waitForHandshake` polls see progress.
        var handshakeAfterSetEndpointMs: Long? = null

        override suspend fun setEndpoint(
            tunnelId: String, candidate: EndpointUpdate, egressInterface: String?,
        ) {
            setEndpointCalls += candidate
            handshakeAfterSetEndpointMs?.let { delayMs ->
                @OptIn(kotlinx.coroutines.DelicateCoroutinesApi::class)
                GlobalScope.launch {
                    delay(delayMs)
                    handshakeMs.set(System.currentTimeMillis())
                }
            }
        }
        override suspend fun latestHandshakeMs() = handshakeMs.get()
        override suspend fun bringDown() { bringDownCalls.incrementAndGet() }
    }

    /** UDP probe that returns Reachable immediately — fastest path
     * through `probeAllCandidates`, so the race iteration starts
     * with no probe-budget delay. */
    private class ReachableProbe : UdpProbe {
        override suspend fun probeOnce(
            ip: String, port: Int, timeoutMs: Long,
        ): ProbeResult = ProbeResult.Reachable
    }

    /** Build a runner whose pre-race window is short enough that
     * tests don't pay the full 2.5 s default. */
    private fun makeRunner(
        controller: TunnelEndpointController,
    ): ConnectionRunner = ConnectionRunner(
        controller, ReachableProbe(),
        preRaceHandshakeWindowMs = 100L,
    )

    private fun lan(ip: String, prefix: Int = 24) =
        LocalInterface("wlan0", ip, prefix)

    // ─── 1. Stale handshake → re-race fires ──────────────────────────

    @Test fun `network change with stale handshake triggers re-race`() = runBlocking {
        // Old handshake well outside the staleness window — roam should
        // kick a re-race.
        val nowMs = AtomicLong(60_000L)
        val controller = ScriptController(initialHandshakeMs = 1_000L).apply {
            // Re-race iteration will succeed quickly on candidate #1.
            handshakeAfterSetEndpointMs = 20L
        }
        val runner = makeRunner(controller)
        val done = CompletableDeferred<ConnectAttemptResult>()
        val roam = RoamController(
            tunnelId = "t1",
            controller = controller,
            runner = runner,
            candidateProvider = { listOf(ep("203.0.113.5"), ep("10.0.0.5")) },
            ifaceProvider = { listOf(lan("10.0.0.99")) },
            scope = CoroutineScope(coroutineContext),
            settleDelayMs = 50L,
            staleHandshakeMs = 30_000L,
            nowMs = { nowMs.get() },
            perCandidateTimeoutMs = 500L,
            probeBudgetMs = 30L,
            onResult = { done.complete(it) },
        )

        roam.onNetworkChanged()
        val r = done.await()
        assertTrue(r is ConnectAttemptResult.Success, "got $r")
        assertTrue(controller.setEndpointCalls.isNotEmpty(),
                   "re-race must have iterated setEndpoint")
        roam.stop()
    }

    // ─── 2. Fresh handshake → re-race skipped ────────────────────────

    @Test fun `network change with fresh handshake skips re-race`() = runBlocking {
        // Handshake just happened — well within the staleness window.
        val nowMs = AtomicLong(60_000L)
        val controller = ScriptController(initialHandshakeMs = 59_500L)
        val runner = makeRunner(controller)
        var resultSeen: ConnectAttemptResult? = null
        val roam = RoamController(
            tunnelId = "t1",
            controller = controller,
            runner = runner,
            candidateProvider = { listOf(ep("203.0.113.5")) },
            ifaceProvider = { emptyList() },
            scope = CoroutineScope(coroutineContext),
            settleDelayMs = 50L,
            staleHandshakeMs = 30_000L,
            nowMs = { nowMs.get() },
            perCandidateTimeoutMs = 500L,
            probeBudgetMs = 30L,
            onResult = { resultSeen = it },
        )

        roam.onNetworkChanged()
        // Wait past the settle window — the roam check should fire and
        // decide to skip the re-race.
        delay(200L)
        assertTrue(controller.setEndpointCalls.isEmpty(),
                   "fresh handshake must skip re-race")
        assertNull(resultSeen,
                   "no race ran → onResult must not fire")
        roam.stop()
    }

    // ─── 3. Back-to-back network changes coalesce into one re-race ──

    @Test fun `back-to-back network changes are debounced to one re-race`() = runBlocking {
        val nowMs = AtomicLong(60_000L)
        val controller = ScriptController(initialHandshakeMs = 1_000L).apply {
            handshakeAfterSetEndpointMs = 20L
        }
        val runner = makeRunner(controller)
        val raceCount = AtomicInteger(0)
        val roam = RoamController(
            tunnelId = "t1",
            controller = controller,
            runner = runner,
            candidateProvider = { listOf(ep("203.0.113.5")) },
            ifaceProvider = { emptyList() },
            scope = CoroutineScope(coroutineContext),
            settleDelayMs = 100L,
            staleHandshakeMs = 30_000L,
            nowMs = { nowMs.get() },
            onResult = { raceCount.incrementAndGet() },
            perCandidateTimeoutMs = 500L,
            probeBudgetMs = 30L,
        )

        // Three network changes within the settle window — only the
        // last one's check should actually fire.
        roam.onNetworkChanged()
        delay(20L)
        roam.onNetworkChanged()
        delay(20L)
        roam.onNetworkChanged()
        // Wait well past settle + race time.
        delay(800L)
        assertEquals(1, raceCount.get(),
                     "rapid network-change burst should produce a single re-race")
        roam.stop()
    }

    // ─── 4. stop() during pending check cancels the re-race ─────────

    @Test fun `stop during pending check cancels the re-race`() = runBlocking {
        val nowMs = AtomicLong(60_000L)
        val controller = ScriptController(initialHandshakeMs = 1_000L).apply {
            handshakeAfterSetEndpointMs = 20L
        }
        val runner = makeRunner(controller)
        var resultSeen: ConnectAttemptResult? = null
        val roam = RoamController(
            tunnelId = "t1",
            controller = controller,
            runner = runner,
            candidateProvider = { listOf(ep("203.0.113.5")) },
            ifaceProvider = { emptyList() },
            scope = CoroutineScope(coroutineContext),
            settleDelayMs = 200L,
            staleHandshakeMs = 30_000L,
            nowMs = { nowMs.get() },
            onResult = { resultSeen = it },
        )

        roam.onNetworkChanged()
        // Stop BEFORE the settle window expires.
        delay(50L)
        roam.stop()
        // Verify nothing fires even after the original settle window
        // would have ended.
        delay(500L)
        assertTrue(controller.setEndpointCalls.isEmpty(),
                   "stop() must cancel the pending re-race")
        assertNull(resultSeen)
    }

    // ─── 5. Re-race uses fresh interfaces, not stale ─────────────────

    @Test fun `re-race uses freshly-enumerated local interfaces`() = runBlocking {
        // The ifaceProvider is called per re-race attempt, not once at
        // construction. Verify by mutating the returned value
        // between two roam events.
        val nowMs = AtomicLong(60_000L)
        val controller = ScriptController(initialHandshakeMs = 1_000L).apply {
            handshakeAfterSetEndpointMs = 20L
        }
        val runner = makeRunner(controller)
        val ifaceCallCount = AtomicInteger(0)
        val provided = mutableListOf<List<LocalInterface>>()
        val ifaceLists = listOf(
            listOf(lan("10.0.0.99")),
            listOf(lan("203.0.113.99")),
        )
        val raceDone = CompletableDeferred<Unit>()
        val raceTwoDone = CompletableDeferred<Unit>()
        val roam = RoamController(
            tunnelId = "t1",
            controller = controller,
            runner = runner,
            candidateProvider = { listOf(ep("10.0.0.5")) },
            ifaceProvider = {
                val idx = ifaceCallCount.getAndIncrement().coerceAtMost(ifaceLists.size - 1)
                ifaceLists[idx].also { provided += it }
            },
            scope = CoroutineScope(coroutineContext),
            settleDelayMs = 50L,
            staleHandshakeMs = 30_000L,
            nowMs = { nowMs.get() },
            perCandidateTimeoutMs = 500L,
            probeBudgetMs = 30L,
            onResult = {
                when (ifaceCallCount.get()) {
                    1 -> raceDone.complete(Unit)
                    2 -> raceTwoDone.complete(Unit)
                }
            },
        )

        roam.onNetworkChanged()
        raceDone.await()
        // Simulate handshake going stale again (e.g., the previous race
        // settled but the new network re-shifted).
        controller.setHandshakeMs(1_000L)
        roam.onNetworkChanged()
        raceTwoDone.await()
        assertEquals(2, ifaceCallCount.get(),
                     "ifaceProvider must be re-invoked per re-race")
        assertEquals(2, provided.size)
        assertTrue(provided[0] != provided[1],
                   "second re-race must see the fresh interface list, not the cached one")
        roam.stop()
    }

    // ─── 6, 7. Race result forwarded to onResult ────────────────────

    @Test fun `re-race success result is forwarded to onResult`() = runBlocking {
        val nowMs = AtomicLong(60_000L)
        val controller = ScriptController(initialHandshakeMs = 1_000L).apply {
            handshakeAfterSetEndpointMs = 20L
        }
        val runner = makeRunner(controller)
        val seen = CompletableDeferred<ConnectAttemptResult>()
        val roam = RoamController(
            tunnelId = "t1",
            controller = controller,
            runner = runner,
            candidateProvider = { listOf(ep("203.0.113.5")) },
            ifaceProvider = { emptyList() },
            scope = CoroutineScope(coroutineContext),
            settleDelayMs = 50L,
            staleHandshakeMs = 30_000L,
            nowMs = { nowMs.get() },
            perCandidateTimeoutMs = 500L,
            probeBudgetMs = 30L,
            onResult = { seen.complete(it) },
        )
        roam.onNetworkChanged()
        val r = seen.await()
        assertTrue(r is ConnectAttemptResult.Success)
        roam.stop()
    }

    @Test fun `re-race failure result is forwarded to onResult`() = runBlocking {
        val nowMs = AtomicLong(60_000L)
        val controller = ScriptController(initialHandshakeMs = 1_000L)
        // No handshakeAfterSetEndpointMs → setEndpoint succeeds but
        // handshake never advances; the race times out and reports
        // Failed.
        val runner = ConnectionRunner(
            controller, ReachableProbe(),
            preRaceHandshakeWindowMs = 50L,
        )
        val seen = CompletableDeferred<ConnectAttemptResult>()
        val roam = RoamController(
            tunnelId = "t1",
            controller = controller,
            runner = runner,
            candidateProvider = { listOf(ep("203.0.113.5")) },
            ifaceProvider = { emptyList() },
            scope = CoroutineScope(coroutineContext),
            settleDelayMs = 30L,
            staleHandshakeMs = 30_000L,
            nowMs = { nowMs.get() },
            onResult = { seen.complete(it) },
            perCandidateTimeoutMs = 300L,
            probeBudgetMs = 30L,
        )
        roam.onNetworkChanged()
        val r = seen.await()
        assertTrue(r is ConnectAttemptResult.Failed,
                   "race with no fresh handshake must report Failed")
        roam.stop()
    }
}
