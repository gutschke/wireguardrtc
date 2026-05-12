package com.gutschke.wgrtc.data

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * **UDP forwarder handler unit tests.**
 *
 * The actual gvisor-coupled datagram path is exercised by the
 * instrumented test. Here we pin:
 *
 * - The flow-keying logic — same (peer, dest) re-uses one
 * "outbound socket" abstraction, different ones get
 * different sockets.
 * - Resolver refusal → flow closed, no socket opened.
 * - Idle timeout reaper — virtual-time test.
 * - DNS dispatch — flows to port 53 with a registered DnsProxy
 * bypass the OS socket entirely and reply via the proxy.
 *
 * Fakes: an in-memory `FakeUdpEgress` stand-in for what a real
 * `DatagramSocket` would do, so the test is fast + deterministic.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class UdpForwarderHandlerTest {

    private class FakeUdpEgress : UdpEgress {
        val sentPackets = mutableListOf<Pair<InetSocketAddress, ByteArray>>()
        val replies = ArrayDeque<ByteArray>()
        var closed = false
        var onSendReply: (() -> ByteArray?)? = null
        override fun send(target: InetSocketAddress, data: ByteArray) {
            if (closed) throw java.io.IOException("closed")
            sentPackets += target to data.copyOf()
        }
        override fun receive(timeoutMs: Int): ByteArray? {
            if (closed) return null
            onSendReply?.invoke()?.let { return it }
            return replies.removeFirstOrNull()
        }
        override fun close() { closed = true }
    }

    private class TrackingFactory : UdpEgressFactory {
        val createdFor = mutableListOf<InetSocketAddress>()
        val instances = mutableListOf<FakeUdpEgress>()
        override fun open(target: InetSocketAddress): UdpEgress {
            createdFor += target
            return FakeUdpEgress().also { instances += it }
        }
    }

    // ── Tests ────────────────────────────────────────────────

    @Test fun resolverRefusalClosesFlowWithoutOpeningSocket() = runTest {
        val factory = TrackingFactory()
        val flowClosed = ConcurrentHashMap<Int, Boolean>()
        val handler = UdpForwarderHandler(
            egressFactory = factory,
            targetResolver = { _, _ -> null },
            onFlowClose = { id, _ -> flowClosed[id] = true },
            ioDispatcher = UnconfinedTestDispatcher(testScheduler),
            startReaders = false,
        )
        handler.dispatch(
            scope = this, flowId = 1,
            peerAddr = "10.99.0.2:1111", origDest = "1.2.3.4:5",
            payload = byteArrayOf(1, 2, 3),
        )
        runCurrent()
        assertEquals(0, factory.createdFor.size,
            "factory must NOT be called when resolver refuses")
        assertEquals(true, flowClosed[1], "flow must be closed on refuse")
    }

    @Test fun samePeerAndDestReuseSameSocket() = runTest {
        val factory = TrackingFactory()
        val handler = UdpForwarderHandler(
            egressFactory = factory,
            targetResolver = { _, dest ->
                val (h, p) = dest.split(':').let { it[0] to it[1].toInt() }
                InetSocketAddress(h, p)
            },
            ioDispatcher = UnconfinedTestDispatcher(testScheduler),
            startReaders = false,
        )
        handler.dispatch(this, 1, "10.99.0.2:1111", "1.2.3.4:5", byteArrayOf(1))
        // runCurrent() runs ready tasks at the current virtual
        // time WITHOUT advancing time, so the idle reaper
        // (which uses delay()) doesn't fire and accidentally
        // close the flow between dispatches.
        runCurrent()
        handler.dispatch(this, 1, "10.99.0.2:1111", "1.2.3.4:5", byteArrayOf(2))
        runCurrent()
        assertEquals(1, factory.createdFor.size,
            "two datagrams in same flow must share one socket")
        val sent = factory.instances[0].sentPackets
        assertEquals(2, sent.size, "both datagrams must reach the socket")
        assertArrayEquals(byteArrayOf(1), sent[0].second)
        assertArrayEquals(byteArrayOf(2), sent[1].second)
    }

    @Test fun differentFlowsGetDifferentSockets() = runTest {
        val factory = TrackingFactory()
        val handler = UdpForwarderHandler(
            egressFactory = factory,
            targetResolver = { _, dest ->
                val (h, p) = dest.split(':').let { it[0] to it[1].toInt() }
                InetSocketAddress(h, p)
            },
            ioDispatcher = UnconfinedTestDispatcher(testScheduler),
            startReaders = false,
        )
        handler.dispatch(this, 1, "10.99.0.2:1111", "1.2.3.4:5", byteArrayOf(1))
        handler.dispatch(this, 2, "10.99.0.2:1111", "1.2.3.4:9", byteArrayOf(1))
        runCurrent()
        assertEquals(2, factory.createdFor.size, "two flowIds = two sockets")
    }

    @Test fun dnsProxyHandlesPort53WithoutOpeningSocket() = runTest {
        val factory = TrackingFactory()
        val replyDispatched = mutableListOf<ByteArray>()
        // Fake DnsResolver: any query gets a canned 5-byte
        // "response" so the proxy's handle() returns non-null.
        val proxy = DnsProxy(object : DnsResolver {
            override fun resolve(name: String): List<java.net.InetAddress> =
                listOf(java.net.Inet4Address.getByAddress(byteArrayOf(1, 2, 3, 4)))
        })
        val handler = UdpForwarderHandler(
            egressFactory = factory,
            targetResolver = { _, dest ->
                val (h, p) = dest.split(':').let { it[0] to it[1].toInt() }
                InetSocketAddress(h, p)
            },
            dnsProxy = proxy,
            replyInjector = { _, bytes -> replyDispatched += bytes },
            ioDispatcher = UnconfinedTestDispatcher(testScheduler),
            startReaders = false,
        )
        // Build a minimal A query for `example.com`.
        val query = buildAQuery(0xABCD, "example.com")
        handler.dispatch(this, 1, "10.99.0.2:54321", "10.99.0.1:53", query)
        runCurrent()
        assertEquals(0, factory.createdFor.size,
            "DNS dispatch must bypass the OS-socket factory")
        assertEquals(1, replyDispatched.size, "exactly one DNS reply injected")
        // First two bytes = txid (mirrored from query)
        assertEquals(0xAB.toByte(), replyDispatched[0][0])
        assertEquals(0xCD.toByte(), replyDispatched[0][1])
    }

    @Test fun idleTimeoutReapsTheFlow() = runTest {
        val factory = TrackingFactory()
        val closed = ConcurrentHashMap<Int, Boolean>()
        val handler = UdpForwarderHandler(
            egressFactory = factory,
            targetResolver = { _, dest ->
                val (h, p) = dest.split(':').let { it[0] to it[1].toInt() }
                InetSocketAddress(h, p)
            },
            idleTimeoutMs = 1_000L,
            onFlowClose = { id, _ -> closed[id] = true },
            ioDispatcher = UnconfinedTestDispatcher(testScheduler),
            startReaders = false,
            // Bind the handler's clock to virtual time so the
            // reaper sees `advanceTimeBy` move "now" forward.
            nowMsProvider = { testScheduler.currentTime },
        )
        handler.dispatch(this, 1, "10.99.0.2:1111", "1.2.3.4:5", byteArrayOf(1))
        runCurrent()
        assertNull(closed[1], "flow should still be alive before timeout")
        // Virtual-time advance past the idle timeout — now the
        // reaper's delay()s fire and the flow's lastActivity
        // (= 0) is more than 1000 ms old.
        advanceTimeBy(1_500L)
        runCurrent()
        assertEquals(true, closed[1], "flow must be closed after idle timeout")
        assertTrue(factory.instances[0].closed,
            "underlying socket must be closed on timeout")
    }

    private fun buildAQuery(txid: Int, name: String): ByteArray {
        val labels = name.trim('.').split('.').filter { it.isNotEmpty() }
        val qnameSize = labels.sumOf { 1 + it.length } + 1
        val buf = ByteArray(12 + qnameSize + 4)
        buf[0] = (txid ushr 8 and 0xff).toByte(); buf[1] = (txid and 0xff).toByte()
        buf[2] = 0x01; buf[5] = 1
        var p = 12
        for (l in labels) {
            buf[p++] = l.length.toByte()
            for (c in l) buf[p++] = c.code.toByte()
        }
        buf[p++] = 0; buf[p++] = 0; buf[p++] = 1
        buf[p++] = 0; buf[p] = 1
        return buf
    }
}
