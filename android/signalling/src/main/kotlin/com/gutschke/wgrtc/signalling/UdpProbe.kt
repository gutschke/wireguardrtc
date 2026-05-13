package com.gutschke.wgrtc.signalling

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.PortUnreachableException
import java.net.SocketException
import java.net.SocketTimeoutException

/**
 * Receiver-side candidate probe — Step E of the candidate-negotiation
 * v2 design.
 *
 * Per-candidate UDP probe with staggered retries inside a wall-clock
 * budget. Three outcomes:
 *
 * [ProbeResult.Reachable] — datagram received back (rare; daemons
 * don't echo, but this catches the case
 * where another service on the port does).
 * [ProbeResult.Unreachable] — synchronous ICMP-derived error
 * (`ENETUNREACH` / `EHOSTUNREACH` /
 * `ECONNREFUSED`). Eliminates the
 * candidate from the race in Step F.
 * [ProbeResult.Silent] — no datagram and no error within budget.
 * Common case for a real WG peer (kernel
 * WG silently drops non-WG-protocol
 * packets). Candidate is KEPT for the
 * race — silence is plausible, and a
 * 5 s WG handshake timeout will catch
 * the genuinely-unreachable ones.
 *
 * Retry schedule (default `[0, 300, 900]` ms with a `1500` ms total
 * budget) tolerates two consecutive packet drops on a flaky
 * Wi-Fi link without penalising fast paths — a same-LAN candidate
 * typically responds (or definitively errors) on the first attempt
 * inside ~10 ms. See the memo §"Probe protocol" for the rationale
 * behind the chosen timings.
 *
 * Real-network semantics (which OS surfaces ICMP unreachable as a
 * sync exception, etc.) are platform-dependent enough that they're
 * verified in Step F's integration tests — this file's unit tests
 * exercise the retry/budget logic with an injectable [UdpProbe]
 * fake.
 */

enum class ProbeResult { Reachable, Unreachable, Silent }

data class ProbeOutcome(
    val result: ProbeResult,
    /** Round-trip time of the *first* attempt that produced this
     * result, or null if the result is [ProbeResult.Silent]
     * (since we never observed a response). */
    val rttMs: Long? = null,
)

/** Single-attempt probe — abstracted so unit tests can fake it
 * (real-network ICMP behavior varies wildly by OS / iface mix). */
interface UdpProbe {
    /** Attempt one probe to `<ip>:<port>` with the given timeout.
     * Implementations MUST NOT throw; all errors fold into one of
     * the three [ProbeResult] values. */
    suspend fun probeOnce(ip: String, port: Int, timeoutMs: Long): ProbeResult
}

/** Production probe. Connects a UDP socket, sends a 1-byte payload,
 * reads with the supplied timeout. Catches the OS-level errors that
 * surface as exceptions and maps to [ProbeResult].
 *
 * The 1-byte payload is intentional: it's not a valid WG handshake
 * message, so the daemon's WG kernel silently drops it. We're not
 * trying to elicit a reply — we're trying to provoke an ICMP error
 * if the path is broken at the network layer. */
class RealUdpProbe : UdpProbe {
    override suspend fun probeOnce(
        ip: String, port: Int, timeoutMs: Long,
    ): ProbeResult = withContext(Dispatchers.IO) {
        val socket = DatagramSocket()
        try {
            socket.connect(InetSocketAddress(ip, port))
            socket.soTimeout = timeoutMs.coerceIn(1, Int.MAX_VALUE.toLong()).toInt()
            socket.send(DatagramPacket(byteArrayOf(0), 1))
            val buf = ByteArray(64)
            socket.receive(DatagramPacket(buf, buf.size))
            ProbeResult.Reachable
        } catch (_: SocketTimeoutException) {
            ProbeResult.Silent
        } catch (_: PortUnreachableException) {
            ProbeResult.Unreachable
        } catch (_: NoRouteToHostException) {
            ProbeResult.Unreachable
        } catch (e: SocketException) {
            // ENETUNREACH / EHOSTUNREACH / connect-refused all surface
            // here on Linux/Android; the message text varies. Treat
            // the whole class as Unreachable when the message hints at
            // routing — fall back to Silent otherwise so a "no buffer
            // space" or similar transient doesn't poison the candidate.
            val msg = e.message?.lowercase().orEmpty()
            if ("unreach" in msg || "no route" in msg || "refused" in msg)
                ProbeResult.Unreachable
            else ProbeResult.Silent
        } catch (_: Exception) {
            ProbeResult.Silent
        } finally {
            try { socket.close() } catch (_: Exception) {}
        }
    }
}

/**
 * Probe one candidate with the staggered-retry schedule. A
 * [ProbeResult.Unreachable] returns immediately (definitive — no
 * point retrying); [ProbeResult.Reachable] also returns immediately
 * (we got our answer). [ProbeResult.Silent] triggers the next
 * attempt up to the schedule's length, capped by [totalBudgetMs].
 *
 * If the schedule outlasts the budget, the function exits early with
 * [ProbeResult.Silent] — the budget wins.
 */
suspend fun probeCandidateWithRetry(
    probe: UdpProbe, ip: String, port: Int,
    schedule: List<Long> = listOf(0L, 300L, 900L),
    totalBudgetMs: Long = 1_500L,
    nowMs: () -> Long = { System.currentTimeMillis() },
): ProbeOutcome {
    val deadline = nowMs() + totalBudgetMs
    val tStart = nowMs()
    for ((i, off) in schedule.withIndex()) {
        val now = nowMs()
        if (now >= deadline) break
        val sleepFor = (tStart + off - now).coerceAtLeast(0L)
        if (sleepFor > 0) {
            // Don't sleep past the deadline.
            val remaining = (deadline - now).coerceAtLeast(0L)
            if (sleepFor >= remaining) break
            delay(sleepFor)
        }
        val perAttemptTimeout = (deadline - nowMs()).coerceAtLeast(1L)
        val attemptStart = nowMs()
        val r = probe.probeOnce(ip, port, perAttemptTimeout)
        val rtt = nowMs() - attemptStart
        when (r) {
            ProbeResult.Reachable -> return ProbeOutcome(r, rtt)
            ProbeResult.Unreachable -> return ProbeOutcome(r, rtt)
            ProbeResult.Silent -> if (i == schedule.lastIndex) break
        }
    }
    return ProbeOutcome(ProbeResult.Silent, null)
}

/**
 * Probe every candidate in parallel, returning a list aligned with
 * the input order: `result[i]` is `candidates[i]`'s outcome. Used
 * by the connection-setup layer (Step F) to filter the picker's
 * output before the WG handshake race.
 */
suspend fun probeAllCandidates(
    probe: UdpProbe,
    candidates: List<EndpointUpdate>,
    schedule: List<Long> = listOf(0L, 300L, 900L),
    totalBudgetMs: Long = 1_500L,
): List<ProbeOutcome> = coroutineScope {
    candidates.map { c ->
        async(Dispatchers.IO) {
            probeCandidateWithRetry(probe, c.ip, c.port, schedule, totalBudgetMs)
        }
    }.awaitAll()
}
