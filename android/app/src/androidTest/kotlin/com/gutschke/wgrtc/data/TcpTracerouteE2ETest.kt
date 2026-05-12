package com.gutschke.wgrtc.data

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetAddress
import java.net.ServerSocket
import java.util.concurrent.atomic.AtomicBoolean

/**
 * **TcpTraceroute smoke test on emulator.**
 *
 * We can't test full multi-hop traces inside an emulator (the
 * loopback path is one hop), but we CAN pin the basics:
 *
 * 1. Connecting to a real, listening port on loopback with
 * TTL=1 succeeds — the trace stops at hop 1.
 * 2. Connecting to a closed loopback port returns
 * REACHED_CLOSED (the loopback kernel RSTs immediately).
 * 3. The trace gives up at maxHops when the target is on an
 * unrouted address.
 *
 * Multi-hop validation is left for real-device + real-network
 * runs — `traceroute -T <something on the public internet>`
 * is the manual diagnostic.
 */
@RunWith(AndroidJUnit4::class)
class TcpTracerouteE2ETest {

    @Volatile private var listener: ServerSocket? = null
    private val running = AtomicBoolean(true)

    @After fun tearDown() {
        running.set(false)
        try { listener?.close() } catch (_: Throwable) {}
    }

    @Test fun loopbackOpenPortReachedOnHop1() = runBlocking {
        val server = ServerSocket(0, 4, InetAddress.getByName("127.0.0.1"))
        listener = server
        val port = server.localPort
        // Accept loop — we don't care about reading, just that
        // the kernel sees the listening socket.
        Thread({
            while (running.get()) {
                try { server.accept().close() } catch (_: Throwable) { break }
            }
        }, "traceroute-test-server").start()

        val tr = TcpTraceroute(maxHops = 3, timeoutMsPerHop = 1000)
        val hops = tr.trace(InetAddress.getByName("127.0.0.1"), port)
        assertEquals("only 1 hop to loopback", 1, hops.size)
        assertEquals(TcpTraceroute.HopStatus.REACHED_OPEN, hops[0].status)
        assertEquals(1, hops[0].ttl)
        assertTrue("hop RTT must be measured", hops[0].rttMs != null)
        assertTrue("hop RTT=${hops[0].rttMs}ms slow",
            hops[0].rttMs!! in 0..500)
    }

    @Test fun loopbackClosedPortReportsReachedClosed() = runBlocking {
        // Bind a server, get a port, immediately close it. The
        // kernel will RST any inbound SYN to the now-closed port.
        val temp = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val deadPort = temp.localPort
        temp.close()
        // Tight race possible if the kernel re-binds the same
        // port to something else, but unlikely in practice.

        val tr = TcpTraceroute(maxHops = 3, timeoutMsPerHop = 1000)
        val hops = tr.trace(InetAddress.getByName("127.0.0.1"), deadPort)
        assertEquals(1, hops.size)
        assertEquals(TcpTraceroute.HopStatus.REACHED_CLOSED, hops[0].status)
    }

    @Test fun unrouteableTargetEventuallyGivesUp() = runBlocking {
        // TEST-NET-2 (RFC 5737) — guaranteed not routable from
        // anywhere. We expect TIMEOUT or UNREACHABLE at every
        // hop and the trace stopping at maxHops.
        val tr = TcpTraceroute(maxHops = 3, timeoutMsPerHop = 500)
        val hops = tr.trace(InetAddress.getByName("198.51.100.42"), 80)
        assertEquals("must try every hop", 3, hops.size)
        hops.forEach {
            assertTrue("hop ${it.ttl} should not be reached",
                !it.isFinalHop)
        }
    }
}
