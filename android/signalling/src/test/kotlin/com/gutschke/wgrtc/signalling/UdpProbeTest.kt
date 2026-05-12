package com.gutschke.wgrtc.signalling

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicInteger

/**
 * Unit tests for the UDP probe retry/budget logic (Step E).
 *
 * Real-network ICMP semantics (which OS surfaces ENETUNREACH as
 * a sync exception, etc.) are too platform-dependent to verify in
 * pure JVM tests — Step F's integration tests on the emulator and
 * physical device cover that. These tests pin the orchestration
 * logic only: retry timing, budget enforcement, parallelism, and
 * outcome-mapping.
 */
class UdpProbeTest {

    private fun ep(ip: String, port: Int = 51820, ts: Long = 1L) =
        EndpointUpdate(ip = ip, port = port, ts = ts)

    /** Fake that returns scripted outcomes by attempt index. */
    private class ScriptedProbe(private val script: List<ProbeResult>) : UdpProbe {
        val attempts = AtomicInteger(0)
        override suspend fun probeOnce(ip: String, port: Int, timeoutMs: Long): ProbeResult {
            val i = attempts.getAndIncrement()
            return script.getOrElse(i) { ProbeResult.Silent }
        }
    }

    /** Fake that always returns the same outcome after a fixed delay. */
    private class DelayedProbe(
        private val outcome: ProbeResult,
        private val delayMs: Long,
    ) : UdpProbe {
        val callCount = AtomicInteger(0)
        override suspend fun probeOnce(ip: String, port: Int, timeoutMs: Long): ProbeResult {
            callCount.incrementAndGet()
            delay(delayMs)
            return outcome
        }
    }

    // ─── single-candidate retry behaviour ─────────────────────────────

    @Test fun `Reachable on first attempt returns immediately`() = runBlocking {
        val probe = ScriptedProbe(listOf(ProbeResult.Reachable))
        val r = probeCandidateWithRetry(probe, "1.2.3.4", 51820)
        assertEquals(ProbeResult.Reachable, r.result)
        assertEquals(1, probe.attempts.get(), "should not retry past success")
    }

    @Test fun `Unreachable on first attempt returns immediately (no retry)`() = runBlocking {
        // Definitive failure: no point retrying.
        val probe = ScriptedProbe(listOf(ProbeResult.Unreachable))
        val r = probeCandidateWithRetry(probe, "1.2.3.4", 51820)
        assertEquals(ProbeResult.Unreachable, r.result)
        assertEquals(1, probe.attempts.get(),
                     "Unreachable is definitive, no retries expected")
    }

    @Test fun `Silent on first, Reachable on second returns Reachable`() = runBlocking {
        // First-packet-loss recovery: the canonical case retry
        // protects against.
        val probe = ScriptedProbe(listOf(
            ProbeResult.Silent,
            ProbeResult.Reachable,
        ))
        // Tight schedule so the test runs fast.
        val r = probeCandidateWithRetry(
            probe, "1.2.3.4", 51820,
            schedule = listOf(0L, 50L), totalBudgetMs = 500L,
        )
        assertEquals(ProbeResult.Reachable, r.result)
        assertEquals(2, probe.attempts.get())
    }

    @Test fun `all-silent within budget yields Silent`() = runBlocking {
        val probe = ScriptedProbe(listOf(
            ProbeResult.Silent, ProbeResult.Silent, ProbeResult.Silent,
        ))
        val r = probeCandidateWithRetry(
            probe, "1.2.3.4", 51820,
            schedule = listOf(0L, 50L, 100L), totalBudgetMs = 500L,
        )
        assertEquals(ProbeResult.Silent, r.result)
        assertEquals(3, probe.attempts.get())
        assertNull(r.rttMs, "no rtt for never-responded candidate")
    }

    @Test fun `Unreachable on later retry returns Unreachable`() = runBlocking {
        val probe = ScriptedProbe(listOf(
            ProbeResult.Silent, ProbeResult.Unreachable,
        ))
        val r = probeCandidateWithRetry(
            probe, "1.2.3.4", 51820,
            schedule = listOf(0L, 50L), totalBudgetMs = 500L,
        )
        assertEquals(ProbeResult.Unreachable, r.result)
    }

    // ─── budget enforcement ──────────────────────────────────────────

    @Test fun `budget cuts off retries even if schedule has more`() = runBlocking {
        // Schedule advances at 0, 200, 400, 600, 800 ms (5 attempts);
        // budget is 250 ms → should run exactly 2 attempts (T=0 and
        // T=200), then exit.
        val probe = ScriptedProbe((1..10).map { ProbeResult.Silent })
        val t0 = System.currentTimeMillis()
        val r = probeCandidateWithRetry(
            probe, "1.2.3.4", 51820,
            schedule = listOf(0L, 200L, 400L, 600L, 800L),
            totalBudgetMs = 250L,
        )
        val elapsed = System.currentTimeMillis() - t0
        assertEquals(ProbeResult.Silent, r.result)
        assertTrue(elapsed < 350L, "should exit within budget+slack; was ${elapsed}ms")
        assertTrue(probe.attempts.get() in 1..3,
                   "expected 1-3 attempts within 250ms; got ${probe.attempts.get()}")
    }

    @Test fun `default schedule with default budget runs up to 3 attempts`() = runBlocking {
        val probe = ScriptedProbe(listOf(
            ProbeResult.Silent, ProbeResult.Silent, ProbeResult.Silent,
            ProbeResult.Reachable, // 4th attempt — should never run
        ))
        val r = probeCandidateWithRetry(probe, "1.2.3.4", 51820)
        assertEquals(ProbeResult.Silent, r.result,
                     "default schedule has 3 attempts; 4th never runs")
        assertEquals(3, probe.attempts.get())
    }

    // ─── parallel probing ────────────────────────────────────────────

    @Test fun `probeAll runs candidates in parallel`() = runBlocking {
        // Three candidates, each takes 100ms. Sequential = 300ms,
        // parallel = ~100ms. Loose bound 200ms catches both wins
        // and avoids flakes on slow CI.
        val probe = DelayedProbe(ProbeResult.Reachable, delayMs = 100)
        val cands = listOf(ep("1.1.1.1"), ep("2.2.2.2"), ep("3.3.3.3"))
        val t0 = System.currentTimeMillis()
        val results = probeAllCandidates(probe, cands, totalBudgetMs = 1_500L)
        val elapsed = System.currentTimeMillis() - t0
        assertEquals(3, results.size)
        results.forEach { assertEquals(ProbeResult.Reachable, it.result) }
        assertTrue(elapsed < 200L,
                   "expected parallel (<200ms); got ${elapsed}ms — sequential would be ~300ms")
        assertEquals(3, probe.callCount.get())
    }

    @Test fun `probeAll returns aligned outcomes per candidate`() = runBlocking {
        // Different candidates get different scripted outcomes —
        // verify alignment is by index.
        val outcomes = listOf(
            ProbeResult.Reachable,
            ProbeResult.Unreachable,
            ProbeResult.Silent,
        )
        // Each candidate gets its own probe instance returning a fixed
        // outcome — simulates a per-candidate routing decision.
        val probes = outcomes.map { o ->
            object : UdpProbe {
                override suspend fun probeOnce(ip: String, port: Int, timeoutMs: Long): ProbeResult = o
            }
        }
        // Since we want per-candidate scripted outcomes but the API
        // takes ONE probe, simulate via a probe that returns based on
        // ip address.
        val ipMap = mapOf("1.1.1.1" to ProbeResult.Reachable,
                          "2.2.2.2" to ProbeResult.Unreachable,
                          "3.3.3.3" to ProbeResult.Silent)
        val probe = object : UdpProbe {
            override suspend fun probeOnce(ip: String, port: Int, timeoutMs: Long): ProbeResult =
                ipMap[ip] ?: ProbeResult.Silent
        }
        val cands = listOf(ep("1.1.1.1"), ep("2.2.2.2"), ep("3.3.3.3"))
        val r = probeAllCandidates(probe, cands)
        assertEquals(ProbeResult.Reachable, r[0].result)
        assertEquals(ProbeResult.Unreachable, r[1].result)
        assertEquals(ProbeResult.Silent, r[2].result)
    }

    @Test fun `probeAll empty input returns empty`() = runBlocking {
        val probe = ScriptedProbe(listOf(ProbeResult.Reachable))
        assertTrue(probeAllCandidates(probe, emptyList()).isEmpty())
    }

    // ─── outcome includes RTT for non-Silent results ──────────────────

    @Test fun `Reachable outcome carries RTT`() = runBlocking {
        val probe = DelayedProbe(ProbeResult.Reachable, delayMs = 50)
        val r = probeCandidateWithRetry(probe, "1.2.3.4", 51820)
        assertEquals(ProbeResult.Reachable, r.result)
        assertNotNull(r.rttMs)
        assertTrue(r.rttMs!! >= 40L && r.rttMs!! < 200L,
                   "RTT should be ~50ms, got ${r.rttMs}ms")
    }

    @Test fun `Silent outcome rttMs is null`() = runBlocking {
        val probe = ScriptedProbe(listOf(
            ProbeResult.Silent, ProbeResult.Silent, ProbeResult.Silent,
        ))
        val r = probeCandidateWithRetry(probe, "1.2.3.4", 51820,
                                         schedule = listOf(0L, 10L, 20L),
                                         totalBudgetMs = 100L)
        assertEquals(ProbeResult.Silent, r.result)
        assertNull(r.rttMs)
    }
}
