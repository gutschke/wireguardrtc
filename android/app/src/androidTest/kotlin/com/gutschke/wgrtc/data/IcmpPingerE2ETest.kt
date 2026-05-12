package com.gutschke.wgrtc.data

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetAddress

/**
 * **IcmpPinger real-socket smoke test.**
 *
 * Pings loopback (127.0.0.1) from the emulator using
 * `Os.socket(SOCK_DGRAM, IPPROTO_ICMP)`. Validates that:
 *
 * - The unprivileged ICMP socket actually opens on the
 * emulator's API-34 kernel (`ping_group_range = 0 2147483647`
 * by default; if the test fails with "permission denied",
 * the emulator image was misconfigured and we should
 * escalate).
 * - Echo request + reply round-trip via the loopback kernel.
 * - Multi-shot ping reports the right packet count + at least
 * one successful RTT.
 *
 * We deliberately use loopback rather than a public IP so the
 * test doesn't need network connectivity + can't be skewed by
 * an upstream firewall.
 */
@RunWith(AndroidJUnit4::class)
class IcmpPingerE2ETest {

    @Test fun singlePingToLoopbackReturnsRtt() = runBlocking {
        val pinger = IcmpPinger()
        val loopback = InetAddress.getByName("127.0.0.1")
        val rtt = pinger.pingOnce(loopback, timeoutMs = 2000)
        assertNotNull("loopback ping returned no RTT — check " +
            "/proc/sys/net/ipv4/ping_group_range on the emulator", rtt)
        rtt!!
        assertTrue("RTT=${rtt}ms suspiciously slow for loopback",
            rtt in 0..1000)
    }

    @Test fun multiplePingsToLoopbackHaveZeroLoss() = runBlocking {
        val pinger = IcmpPinger()
        val loopback = InetAddress.getByName("127.0.0.1")
        val result = pinger.pingMany(loopback,
            count = 3, intervalMs = 50, timeoutMs = 2000)
        assertNull("unexpected fatal error: ${result.errorMessage}",
            result.errorMessage)
        assertEquals(3, result.packetsSent)
        assertEquals("loopback shouldn't drop any packets",
            3, result.packetsReceived)
        assertEquals(0, result.packetLossPct)
        assertEquals(3, result.rttsMs.size)
        // Loopback latency should never exceed ~50ms even on
        // a beaten-down emulator
        result.rttsMs.forEach {
            assertTrue("RTT=${it}ms slow", it in 0..500)
        }
    }

    @Test fun pingUnreachableIpTimesOut() = runBlocking {
        val pinger = IcmpPinger()
        // 198.51.100.0/24 is TEST-NET-2 (RFC 5737) — guaranteed
        // not routable. The kernel may return an immediate
        // "network unreachable" error or a slow timeout; either
        // way we expect packetsReceived = 0 with no fatal error.
        val unreachable = InetAddress.getByName("198.51.100.42")
        val result = pinger.pingMany(unreachable,
            count = 1, intervalMs = 0, timeoutMs = 500)
        assertEquals(1, result.packetsSent)
        assertEquals(0, result.packetsReceived)
        assertEquals(100, result.packetLossPct)
        assertTrue("rtts should be empty on timeout", result.rttsMs.isEmpty())
    }
}
