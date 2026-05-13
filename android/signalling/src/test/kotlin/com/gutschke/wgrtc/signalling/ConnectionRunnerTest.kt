package com.gutschke.wgrtc.signalling

import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.coroutineScope
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicInteger

/**
 * Unit tests for the connection-attempt orchestration (Step F.1).
 *
 * Pure-JVM: the [TunnelEndpointController] is a scripted fake that
 * controls when "handshake completes" surfaces, and the [UdpProbe]
 * fake controls per-candidate outcomes. These tests pin the state
 * machine — picker integration, probe filtering, race ordering,
 * timeout-and-advance, strict-mode termination.
 *
 * Step F.2/F.3 verify the production controller against the real
 * WG backend on the emulator + physical device.
 */
class ConnectionRunnerTest {

    private fun ep(ip: String, port: Int = 51820, ts: Long = 1L) =
        EndpointUpdate(ip = ip, port = port, ts = ts)

    private fun li(name: String, ip: String, prefix: Int) =
        LocalInterface(name, ip, prefix)

    /** Per-candidate scripted UDP outcome (by IP). */
    private class IpKeyedProbe(private val outcomes: Map<String, ProbeResult>) : UdpProbe {
        override suspend fun probeOnce(ip: String, port: Int, timeoutMs: Long): ProbeResult =
            outcomes[ip] ?: ProbeResult.Silent
    }

    /** Controller fake. setEndpoint(c) "schedules" a handshake-completes
     * event after `successAfterIpDelayMs[c.ip]` ms; if absent, never. */
    private class FakeController(
        private val successAfterIpDelayMs: Map<String, Long> = emptyMap(),
        private val rejectIp: Set<String> = emptySet(),
    ) : TunnelEndpointController {
        val setEndpointCalls = mutableListOf<Pair<String, EndpointUpdate>>()
        val bringDownCalls = AtomicInteger(0)
        private val handshakeTimeMs = AtomicLong(0)
        private var pendingTask: kotlinx.coroutines.Job? = null

        override suspend fun setEndpoint(
            tunnelId: String, candidate: EndpointUpdate, egressInterface: String?,
        ) {
            setEndpointCalls += tunnelId to candidate
            if (candidate.ip in rejectIp) throw IllegalStateException("backend rejected ${candidate.ip}")
            // Cancel any outstanding "future handshake" from prior endpoint.
            pendingTask?.cancel()
            pendingTask = null
            val delayMs = successAfterIpDelayMs[candidate.ip] ?: return
            // Schedule the handshake-completion bump on a background
            // coroutine. Tests must runBlocking { coroutineScope { ... } }
            // for this to be picked up by waitForHandshake's polling.
            pendingTask = kotlinx.coroutines.GlobalScope.launch {
                delay(delayMs)
                handshakeTimeMs.set(System.currentTimeMillis())
            }
        }
        override suspend fun latestHandshakeMs() = handshakeTimeMs.get()
        override suspend fun bringDown() { bringDownCalls.incrementAndGet() }
    }

    // ─── trivial cases ────────────────────────────────────────────────

    @Test fun `empty candidates returns Failed`() = runBlocking {
        val controller = FakeController()
        val runner = ConnectionRunner(controller, IpKeyedProbe(emptyMap()), preRaceHandshakeWindowMs = 0L)
        val r = runner.connect("t1", emptyList(), emptyList())
        assertTrue(r is ConnectAttemptResult.Failed)
        assertTrue((r as ConnectAttemptResult.Failed).reason.contains("no candidates"))
        assertEquals(0, controller.setEndpointCalls.size)
    }

    @Test fun `single candidate handshakes immediately`() = runBlocking {
        val controller = FakeController(successAfterIpDelayMs = mapOf("203.0.113.5" to 50L))
        val runner = ConnectionRunner(controller, IpKeyedProbe(emptyMap()), preRaceHandshakeWindowMs = 0L)
        val r = runner.connect("t1", listOf(ep("203.0.113.5")), emptyList(),
                               perCandidateTimeoutMs = 1_000L,
                               probeBudgetMs = 50L)
        assertTrue(r is ConnectAttemptResult.Success, "got $r")
        val s = r as ConnectAttemptResult.Success
        assertEquals("203.0.113.5", s.finalEndpoint.ip)
        assertNull(s.egressInterface)
        assertTrue(s.handshakeWaitMs in 0..500L)
    }

    // ─── probe filter eliminates unreachable ─────────────────────────

    @Test fun `probe Unreachable candidates are skipped`() = runBlocking {
        val controller = FakeController(successAfterIpDelayMs = mapOf("198.51.100.1" to 50L))
        val probe = IpKeyedProbe(mapOf(
            "203.0.113.5" to ProbeResult.Unreachable, // dead path
            "198.51.100.1" to ProbeResult.Silent, // plausible, kept
        ))
        val runner = ConnectionRunner(controller, probe, preRaceHandshakeWindowMs = 0L)
        val r = runner.connect(
            "t1", listOf(ep("203.0.113.5"), ep("198.51.100.1")),
            emptyList(),
            perCandidateTimeoutMs = 1_000L, probeBudgetMs = 100L,
        )
        assertTrue(r is ConnectAttemptResult.Success, "got $r")
        // Only 198.51.100.1 should have been tried; 203.0.113.5
        // pre-eliminated by probe.
        assertEquals(1, controller.setEndpointCalls.size)
        assertEquals("198.51.100.1", controller.setEndpointCalls[0].second.ip)
    }

    @Test fun `all probes Unreachable returns Failed without race`() = runBlocking {
        val controller = FakeController()
        val probe = IpKeyedProbe(mapOf(
            "203.0.113.5" to ProbeResult.Unreachable,
            "198.51.100.1" to ProbeResult.Unreachable,
        ))
        val runner = ConnectionRunner(controller, probe, preRaceHandshakeWindowMs = 0L)
        val r = runner.connect(
            "t1", listOf(ep("203.0.113.5"), ep("198.51.100.1")),
            emptyList(),
            perCandidateTimeoutMs = 1_000L, probeBudgetMs = 100L,
        )
        assertTrue(r is ConnectAttemptResult.Failed)
        assertTrue((r as ConnectAttemptResult.Failed).reason.contains("unreachable"))
        assertEquals(0, controller.setEndpointCalls.size,
                     "race shouldn't run any setEndpoint when all probes failed")
    }

    // ─── race: advance on timeout ────────────────────────────────────

    @Test fun `first candidate times out, second succeeds`() = runBlocking {
        // First candidate (1.1.1.1): never handshakes. Second (2.2.2.2): 50ms.
        val controller = FakeController(successAfterIpDelayMs = mapOf("2.2.2.2" to 50L))
        val runner = ConnectionRunner(controller, IpKeyedProbe(emptyMap()), preRaceHandshakeWindowMs = 0L)
        val r = runner.connect(
            "t1", listOf(ep("1.1.1.1"), ep("2.2.2.2")),
            emptyList(),
            perCandidateTimeoutMs = 500L, // tight timeout for fast test
            probeBudgetMs = 50L,
        )
        assertTrue(r is ConnectAttemptResult.Success, "got $r")
        assertEquals("2.2.2.2", (r as ConnectAttemptResult.Success).finalEndpoint.ip)
        assertEquals(2, controller.setEndpointCalls.size)
    }

    @Test fun `all candidates time out returns Failed`() = runBlocking {
        // No handshake scheduled for either.
        val controller = FakeController()
        val runner = ConnectionRunner(controller, IpKeyedProbe(emptyMap()), preRaceHandshakeWindowMs = 0L)
        val r = runner.connect(
            "t1", listOf(ep("1.1.1.1"), ep("2.2.2.2")),
            emptyList(),
            perCandidateTimeoutMs = 200L, // tight
            probeBudgetMs = 50L,
        )
        assertTrue(r is ConnectAttemptResult.Failed)
        val f = r as ConnectAttemptResult.Failed
        assertTrue(f.reason.contains("no handshake"))
        assertEquals(2, f.triedCandidates.size)
    }

    @Test fun `setEndpoint failure for one candidate advances to next`() = runBlocking {
        val controller = FakeController(
            successAfterIpDelayMs = mapOf("2.2.2.2" to 50L),
            rejectIp = setOf("1.1.1.1"), // backend rejects this config
        )
        val runner = ConnectionRunner(controller, IpKeyedProbe(emptyMap()), preRaceHandshakeWindowMs = 0L)
        val r = runner.connect(
            "t1", listOf(ep("1.1.1.1"), ep("2.2.2.2")),
            emptyList(),
            perCandidateTimeoutMs = 500L, probeBudgetMs = 50L,
        )
        assertTrue(r is ConnectAttemptResult.Success, "got $r")
        assertEquals("2.2.2.2", (r as ConnectAttemptResult.Success).finalEndpoint.ip)
    }

    // ─── strict-mode hotspot data-leak guarantee ─────────────────────

    @Test fun `strict mode does NOT fall through when same-subnet exhausts`() = runBlocking {
        // Hotspot scenario: receiver IS on 192.168.43/24; sender
        // offered LAN+STUN. LAN candidate fails — strict mode must
        // refuse to try the STUN one. This is the load-bearing
        // hotspot data-leak guarantee.
        val controller = FakeController() // no candidate handshakes
        val runner = ConnectionRunner(controller, IpKeyedProbe(emptyMap()), preRaceHandshakeWindowMs = 0L)
        val r = runner.connect(
            "t1",
            listOf(ep("203.0.113.5"), ep("192.168.43.1")), // STUN, LAN
            listOf(li("wlan0", "192.168.43.42", 24)), // on LAN
            strictHotspot = true,
            perCandidateTimeoutMs = 200L, probeBudgetMs = 50L,
        )
        assertTrue(r is ConnectAttemptResult.Failed)
        val f = r as ConnectAttemptResult.Failed
        assertTrue(f.strictModeBlocked, "expected strict-mode block")
        // Crucially: only the LAN candidate was tried; STUN was NOT.
        assertEquals(1, controller.setEndpointCalls.size,
                     "strict mode must not try non-same-subnet candidates")
        assertEquals("192.168.43.1", controller.setEndpointCalls[0].second.ip)
    }

    @Test fun `non-strict mode falls through after same-subnet fails`() = runBlocking {
        val controller = FakeController(successAfterIpDelayMs = mapOf("203.0.113.5" to 50L))
        val runner = ConnectionRunner(controller, IpKeyedProbe(emptyMap()), preRaceHandshakeWindowMs = 0L)
        val r = runner.connect(
            "t1",
            listOf(ep("203.0.113.5"), ep("192.168.43.1")),
            listOf(li("wlan0", "192.168.43.42", 24)),
            strictHotspot = false, // non-strict
            perCandidateTimeoutMs = 200L, probeBudgetMs = 50L,
        )
        assertTrue(r is ConnectAttemptResult.Success, "got $r")
        // Both endpoints attempted: LAN first (same-subnet override),
        // then STUN.
        assertEquals(2, controller.setEndpointCalls.size)
        assertEquals("192.168.43.1", controller.setEndpointCalls[0].second.ip)
        assertEquals("203.0.113.5", controller.setEndpointCalls[1].second.ip)
    }

    @Test fun `strict mode passes through cleanly when no same-subnet match`() = runBlocking {
        // Receiver is NOT on hotspot LAN — strict mode is harmless.
        val controller = FakeController(successAfterIpDelayMs = mapOf("192.168.43.1" to 50L))
        val runner = ConnectionRunner(controller, IpKeyedProbe(emptyMap()), preRaceHandshakeWindowMs = 0L)
        val r = runner.connect(
            "t1",
            listOf(ep("203.0.113.5"), ep("192.168.43.1")),
            listOf(li("wlan0", "10.0.0.5", 24)), // different LAN
            strictHotspot = true,
            perCandidateTimeoutMs = 500L, probeBudgetMs = 50L,
        )
        // No same-subnet match → no override, sender order preserved →
        // 203.0.113.5 tried first, fails (no handshake), then
        // 192.168.43.1 succeeds.
        assertTrue(r is ConnectAttemptResult.Success, "got $r")
    }

    // ─── same-subnet egress is recorded ──────────────────────────────

    @Test fun `success carries egressInterface for same-subnet pick`() = runBlocking {
        val controller = FakeController(successAfterIpDelayMs = mapOf("192.168.43.1" to 30L))
        val runner = ConnectionRunner(controller, IpKeyedProbe(emptyMap()), preRaceHandshakeWindowMs = 0L)
        val r = runner.connect(
            "t1",
            listOf(ep("192.168.43.1")),
            listOf(li("wlan2", "192.168.43.42", 24)),
            perCandidateTimeoutMs = 500L, probeBudgetMs = 50L,
        )
        assertTrue(r is ConnectAttemptResult.Success, "got $r")
        assertEquals("wlan2", (r as ConnectAttemptResult.Success).egressInterface,
                     "egressInterface must reflect the receiver-side same-subnet match")
    }

    // ─── candidates ordered by sender preference when no override ────

    @Test fun `no same-subnet match preserves sender order`() = runBlocking {
        // Sender ranked 203.0.113.5 first. Receiver has no
        // matching local subnet. Race tries in sender order.
        val controller = FakeController(successAfterIpDelayMs = mapOf("203.0.113.5" to 30L))
        val runner = ConnectionRunner(controller, IpKeyedProbe(emptyMap()), preRaceHandshakeWindowMs = 0L)
        val r = runner.connect(
            "t1",
            listOf(ep("203.0.113.5"), ep("198.51.100.1")),
            emptyList(),
            perCandidateTimeoutMs = 500L, probeBudgetMs = 50L,
        )
        assertTrue(r is ConnectAttemptResult.Success, "got $r")
        assertEquals("203.0.113.5", controller.setEndpointCalls[0].second.ip,
                     "sender's rank-0 candidate tried first")
    }

    // ─── pre-race shortcut ──────────────────────────────────────
    //
    // Regression for the "race destroys working session" bug. The
    // caller (WgrtcViewModel.connect) brings wg-go UP with the
    // persisted Endpoint baked in. If that handshake completes before
    // the race starts, the runner MUST NOT call setEndpoint — doing so
    // does a `Removing all peers` + re-create dance that kills the
    // working session.

    private class PreHandshakedController(
        private val handshakeAfterMs: Long,
    ) : TunnelEndpointController {
        val setEndpointCalls = AtomicInteger(0)
        val bringDownCalls = AtomicInteger(0)
        private val started = System.currentTimeMillis()
        override suspend fun setEndpoint(
            tunnelId: String, candidate: EndpointUpdate, egressInterface: String?,
        ) {
            setEndpointCalls.incrementAndGet()
        }
        override suspend fun latestHandshakeMs(): Long {
            val elapsed = System.currentTimeMillis() - started
            return if (elapsed >= handshakeAfterMs) System.currentTimeMillis() else 0L
        }
        override suspend fun bringDown() { bringDownCalls.incrementAndGet() }
    }

    @Test fun `pre-race shortcut returns Success without touching setEndpoint`() = runBlocking {
        // Simulates: bring-up completes a handshake 100 ms after
        // connect() is invoked. Runner sees the handshake during its
        // 1.5-s pre-race poll → returns Success, no race iteration.
        val controller = PreHandshakedController(handshakeAfterMs = 100L)
        val runner = ConnectionRunner(
            controller, IpKeyedProbe(emptyMap()),
            preRaceHandshakeWindowMs = 1_500L,
        )
        val r = runner.connect(
            "t1",
            listOf(ep("203.0.113.5"), ep("10.0.0.5")),
            emptyList(),
        )
        assertTrue(r is ConnectAttemptResult.Success, "got $r")
        assertEquals(0, controller.setEndpointCalls.get(),
                     "pre-race shortcut must skip setEndpoint")
        assertEquals(0, controller.bringDownCalls.get())
        val s = r as ConnectAttemptResult.Success
        assertNull(s.egressInterface,
                   "shortcut path keeps the persisted Endpoint live, not re-persisted")
    }

    @Test fun `pre-race shortcut times out cleanly and falls through to the race`() = runBlocking {
        // Bring-up's handshake never completes. Runner's pre-race
        // poll budget expires after 200 ms; the race then proceeds
        // normally and the (separate) FakeController completes the
        // handshake on candidate #1.
        val controller = FakeController(
            successAfterIpDelayMs = mapOf("203.0.113.5" to 30L),
        )
        val runner = ConnectionRunner(
            controller, IpKeyedProbe(emptyMap()),
            preRaceHandshakeWindowMs = 200L,
        )
        val r = runner.connect(
            "t1",
            listOf(ep("203.0.113.5")),
            emptyList(),
            perCandidateTimeoutMs = 500L, probeBudgetMs = 50L,
        )
        assertTrue(r is ConnectAttemptResult.Success, "got $r")
        assertEquals(1, controller.setEndpointCalls.size,
                     "race must run after the pre-race window expires")
    }

    // ─── don't shortcut when a LAN candidate exists ────────
    //
    // Regression for "endpoint shows external IPv4 instead of the
    // internal LAN one". When the joiner is on the same /24 as the
    // server, the bring-up's handshake against the (public-IP)
    // persisted Endpoint would complete first; the shortcut would
    // then accept it and never upgrade to the LAN candidate.

    @Test fun `pre-race shortcut is skipped when a LAN candidate exists`() = runBlocking {
        // Bring-up handshakes against the persisted public endpoint
        // in 50 ms — fast enough that the shortcut would catch it if
        // it didn't skip. But a same-subnet candidate (10.0.0.5) is
        // also in the OFFER, so the runner must run the full race +
        // setEndpoint(LAN).
        val controller = FakeController(
            successAfterIpDelayMs = mapOf("10.0.0.5" to 30L),
        )
        // Pre-handshakedness has to be simulated separately from
        // FakeController (FakeController only completes after
        // setEndpoint). Use a dedicated controller that bumps
        // handshakeMs after a delay, AND counts setEndpoint calls.
        val combined = object : TunnelEndpointController {
            val setEndpointCalls = mutableListOf<EndpointUpdate>()
            private val started = System.currentTimeMillis()
            override suspend fun setEndpoint(
                tunnelId: String, candidate: EndpointUpdate, egressInterface: String?,
            ) {
                setEndpointCalls += candidate
                // LAN candidate handshakes "instantly".
                if (candidate.ip == "10.0.0.5") {
                    kotlinx.coroutines.GlobalScope.launch {
                        delay(20)
                        @Suppress("ControlFlowWithEmptyBody")
                        do {} while (false)
                    }
                }
            }
            override suspend fun latestHandshakeMs(): Long {
                val elapsed = System.currentTimeMillis() - started
                // Pre-race period: handshake completes against
                // persisted endpoint after 50 ms. After setEndpoint
                // fires for a candidate, that candidate's handshake
                // completes after another 50 ms cumulative.
                return if (elapsed >= 50L) System.currentTimeMillis() else 0L
            }
            override suspend fun bringDown() {}
        }
        val runner = ConnectionRunner(
            combined, IpKeyedProbe(emptyMap()),
            preRaceHandshakeWindowMs = 1_500L,
        )
        val r = runner.connect(
            "t1",
            // Sender order: public first, LAN second. Picker will
            // hoist the same-subnet candidate to the top.
            listOf(ep("203.0.113.5"), ep("10.0.0.5")),
            listOf(li("wlan0", "10.0.0.99", 24)),
            perCandidateTimeoutMs = 1_500L, probeBudgetMs = 50L,
            strictHotspot = false,
        )
        assertTrue(r is ConnectAttemptResult.Success, "got $r")
        // The race MUST have run — at least one setEndpoint call.
        assertTrue(combined.setEndpointCalls.isNotEmpty(),
                   "pre-race shortcut must NOT bypass the race " +
                   "when a same-subnet candidate is available")
        assertEquals("10.0.0.5", combined.setEndpointCalls[0].ip,
                     "race must try the LAN candidate first")
    }

    // ─── pre-race shortcut requires incremental handshake ──
    //
    // Regression for the roam scenario: the controller's
    // latestHandshakeMs carries the OLD endpoint's handshake
    // timestamp into a re-race triggered by RoamController. If the
    // shortcut compared against `prev=0L` it would short-circuit
    // immediately (any past handshake counts) and never re-race.

    @Test fun `pre-race shortcut requires a fresh handshake, not a stale one`() = runBlocking {
        // Controller has an OLD handshake timestamp from before the
        // re-race began — the shortcut must wait for a NEW one to
        // appear, not accept the stale value.
        val staleHandshakeAt = System.currentTimeMillis() - 60_000L
        val controller = object : TunnelEndpointController {
            val setEndpointCalls = mutableListOf<EndpointUpdate>()
            // No fresh-handshake event — `latestHandshakeMs` just
            // returns the stale timestamp forever.
            override suspend fun setEndpoint(
                tunnelId: String, candidate: EndpointUpdate, egressInterface: String?,
            ) { setEndpointCalls += candidate }
            override suspend fun latestHandshakeMs(): Long = staleHandshakeAt
            override suspend fun bringDown() {}
        }
        val runner = ConnectionRunner(
            controller, IpKeyedProbe(emptyMap()),
            preRaceHandshakeWindowMs = 50L,
        )
        val r = runner.connect(
            "t1",
            listOf(ep("203.0.113.5")),
            emptyList(),
            perCandidateTimeoutMs = 200L, probeBudgetMs = 30L,
        )
        // Race must have run (setEndpoint called) — stale handshake
        // shouldn't short-circuit.
        assertTrue(controller.setEndpointCalls.isNotEmpty(),
                   "stale handshake must NOT trigger the pre-race shortcut")
    }

    @Test fun `pre-race shortcut still fires when no LAN candidate exists`() = runBlocking {
        // Bring-up handshakes against the (only) public endpoint in
        // 100 ms. Picker can't promote anything; shortcut should
        // accept the bring-up's handshake without running the race.
        val controller = PreHandshakedController(handshakeAfterMs = 100L)
        val runner = ConnectionRunner(
            controller, IpKeyedProbe(emptyMap()),
            preRaceHandshakeWindowMs = 1_500L,
        )
        val r = runner.connect(
            "t1",
            listOf(ep("203.0.113.5")),
            // No local interfaces match — no same-subnet candidate.
            listOf(li("wlan0", "192.168.1.50", 24)),
        )
        assertTrue(r is ConnectAttemptResult.Success, "got $r")
        assertEquals(0, controller.setEndpointCalls.get(),
                     "shortcut must skip the race when no LAN candidate exists")
    }

    // ─── PS27: cold-start baseline override ──────────────────────────
    //
    // On fast paths (e.g. ARC loopback v6) the initial handshake
    // completes BEFORE runner.connect even starts polling. The
    // default capture-at-entry baseline already reflects the just-
    // completed handshake, so waitForHandshake sits out its full
    // window for a successor that never arrives, then falls through
    // to a redundant race. Cold-start callers (WgrtcViewModel) opt
    // out by passing baselineHandshakeMs=0L — any positive value
    // returned by the controller then counts as fresh.

    @Test fun `baselineHandshakeMs=0L short-circuits when controller already has a handshake`() = runBlocking {
        // Simulates ARC fast-path: the controller's
        // latestHandshakeMs is already > 0 at the moment connect()
        // is invoked (binding.service.start triggered the handshake
        // synchronously). Default behaviour would capture that
        // value as the baseline and never short-circuit. With
        // baselineHandshakeMs=0L the runner accepts the standing
        // handshake immediately and skips the race entirely.
        val already = System.currentTimeMillis()
        val controller = object : TunnelEndpointController {
            val setEndpointCalls = AtomicInteger(0)
            val bringDownCalls = AtomicInteger(0)
            override suspend fun setEndpoint(
                tunnelId: String, candidate: EndpointUpdate, egressInterface: String?,
            ) { setEndpointCalls.incrementAndGet() }
            override suspend fun latestHandshakeMs(): Long = already
            override suspend fun bringDown() { bringDownCalls.incrementAndGet() }
        }
        val runner = ConnectionRunner(
            controller, IpKeyedProbe(emptyMap()),
            preRaceHandshakeWindowMs = 1_500L,
        )
        val r = runner.connect(
            "t1",
            listOf(ep("203.0.113.5")),
            emptyList(),
            perCandidateTimeoutMs = 500L,
            probeBudgetMs = 50L,
            baselineHandshakeMs = 0L,
        )
        assertTrue(r is ConnectAttemptResult.Success, "got $r")
        assertEquals(0, controller.setEndpointCalls.get(),
                     "cold-start baseline=0 must short-circuit on the standing handshake")
        assertEquals(0, controller.bringDownCalls.get())
    }

    @Test fun `default baseline (no override) preserves roam semantics — stale handshake does not short-circuit`() = runBlocking {
        // Same controller as above (handshake already set), but the
        // caller does NOT pass baselineHandshakeMs — this is
        // RoamController's path, where the standing handshake is
        // from the OLD endpoint and must NOT be accepted as "fresh
        // for the new endpoint". Capture-at-entry stays. Pre-race
        // budgets out, race runs.
        val already = System.currentTimeMillis()
        val controller = object : TunnelEndpointController {
            val setEndpointCalls = mutableListOf<EndpointUpdate>()
            override suspend fun setEndpoint(
                tunnelId: String, candidate: EndpointUpdate, egressInterface: String?,
            ) { setEndpointCalls += candidate }
            override suspend fun latestHandshakeMs(): Long = already
            override suspend fun bringDown() {}
        }
        val runner = ConnectionRunner(
            controller, IpKeyedProbe(emptyMap()),
            preRaceHandshakeWindowMs = 100L,
        )
        val r = runner.connect(
            "t1",
            listOf(ep("203.0.113.5")),
            emptyList(),
            perCandidateTimeoutMs = 200L,
            probeBudgetMs = 30L,
            // baselineHandshakeMs intentionally omitted.
        )
        assertTrue(controller.setEndpointCalls.isNotEmpty(),
                   "default capture-at-entry baseline must NOT short-circuit on a standing handshake")
    }
}
