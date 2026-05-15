package com.gutschke.wgrtc.data

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.net.InetSocketAddress
import java.util.Collections
import java.util.concurrent.atomic.AtomicInteger

/**
 * Tests for [UserspaceWgEndpoint.listenUdp] — the per-peer demuxer
 * that turns the bridge's single-handler API into one
 * [WgUdpFlow] per (peerAddr) pair.
 *
 * Uses [runTest] with virtual time: launches dispatch on the test
 * scheduler so the test thread isn't racing wall-clock latency
 * against `Dispatchers.Default`.  [delay] calls advance virtual
 * time instantly.  Background coroutines auto-cancel when the
 * test returns (via [backgroundScope]), so no manual SupervisorJob
 * + tearDown is needed.
 */
class UserspaceWgEndpointUdpTest {

    @Test
    fun `listenUdp registers with backend at the right port`() = runTest {
        val backend = UdpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        endpoint.listenUdp(53, backgroundScope, { _, _ -> InetSocketAddress("8.8.8.8", 53) }) {}
        assertEquals(listOf(53), backend.udpPorts)
    }

    @Test
    fun `first datagram from new peer creates a flow`() = runTest {
        val backend = UdpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        val seen = CompletableDeferred<WgUdpFlow>()
        endpoint.listenUdp(
            port = 53,
            scope = backgroundScope,
            targetResolver = { _, _ -> InetSocketAddress("8.8.8.8", 53) },
            onFlow = { flow -> seen.complete(flow); flow.receive() /* keep open */; flow.close() },
        )
        backend.fireUdpDatagram("10.99.0.2:7777", "10.99.0.1:53", "hi".toByteArray())
        val flow = seen.await()
        assertEquals("10.99.0.2", flow.peerAddress.hostString)
        assertEquals(7777, flow.peerAddress.port)
        assertEquals(InetSocketAddress("8.8.8.8", 53), flow.targetAddress)
    }

    @Test
    fun `flow receive yields the datagrams routed to that peer`() = runTest {
        val backend = UdpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        val received = Collections.synchronizedList(mutableListOf<String>())
        val flowReady = CompletableDeferred<WgUdpFlow>()
        endpoint.listenUdp(
            port = 53,
            scope = backgroundScope,
            targetResolver = { _, _ -> InetSocketAddress("8.8.8.8", 53) },
            onFlow = { flow ->
                flowReady.complete(flow)
                while (true) {
                    val d = flow.receive() ?: break
                    received += String(d)
                }
            },
        )
        backend.fireUdpDatagram("10.99.0.2:1", "10.99.0.1:53", "one".toByteArray())
        val flow = flowReady.await()
        backend.fireUdpDatagram("10.99.0.2:1", "10.99.0.1:53", "two".toByteArray())
        backend.fireUdpDatagram("10.99.0.2:1", "10.99.0.1:53", "three".toByteArray())
        runCurrent() // let the consumer drain the channel
        flow.close()
        assertEquals(listOf("one", "two", "three"), received.toList())
    }

    @Test
    fun `datagrams from different peers create separate flows`() = runTest {
        val backend = UdpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        val flowsSeen = Collections.synchronizedList(mutableListOf<WgUdpFlow>())
        endpoint.listenUdp(
            port = 53,
            scope = backgroundScope,
            targetResolver = { _, _ -> InetSocketAddress("8.8.8.8", 53) },
            onFlow = { flow -> flowsSeen += flow; flow.receive(); flow.close() },
        )
        backend.fireUdpDatagram("10.99.0.2:1", "10.99.0.1:53", "a".toByteArray())
        backend.fireUdpDatagram("10.99.0.3:1", "10.99.0.1:53", "b".toByteArray())
        runCurrent()
        assertEquals(2, flowsSeen.size)
        assertNotSame(flowsSeen[0], flowsSeen[1])
        assertEquals("10.99.0.2", flowsSeen[0].peerAddress.hostString)
        assertEquals("10.99.0.3", flowsSeen[1].peerAddress.hostString)
    }

    @Test
    fun `null target drops the datagram silently`() = runTest {
        val backend = UdpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        val flowCount = AtomicInteger(0)
        endpoint.listenUdp(
            port = 53,
            scope = backgroundScope,
            targetResolver = { _, _ -> null },
            onFlow = { flowCount.incrementAndGet(); it.close() },
        )
        backend.fireUdpDatagram("10.99.0.2:1", "10.99.0.1:53", "drop me".toByteArray())
        runCurrent()
        assertEquals(0, flowCount.get())
    }

    @Test
    fun `flow send routes back to sink with right peer`() = runTest {
        val backend = UdpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        val flowReady = CompletableDeferred<WgUdpFlow>()
        endpoint.listenUdp(
            port = 53,
            scope = backgroundScope,
            targetResolver = { _, _ -> InetSocketAddress("8.8.8.8", 53) },
            onFlow = { flow ->
                flowReady.complete(flow)
                flow.receive() // wait for incoming
                flow.send("reply".toByteArray())
                flow.close()
            },
        )
        backend.fireUdpDatagram("10.99.0.2:42", "10.99.0.1:53", "ping".toByteArray())
        val flow = flowReady.await()
        runCurrent()
        assertEquals(1, backend.sink.sends.size)
        val (peer, data) = backend.sink.sends[0]
        assertEquals("10.99.0.2:42", peer)
        assertArrayEquals("reply".toByteArray(), data)
        // Suppress "flow unused" lint.
        assertEquals("10.99.0.2", flow.peerAddress.hostString)
    }

    @Test
    fun `flow is removed from demux when onFlow returns and closing reopens`() = runTest {
        val backend = UdpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        val flows = Collections.synchronizedList(mutableListOf<WgUdpFlow>())
        endpoint.listenUdp(
            port = 53,
            scope = backgroundScope,
            targetResolver = { _, _ -> InetSocketAddress("8.8.8.8", 53) },
            onFlow = { flow -> flows += flow; flow.receive(); flow.close() },
        )
        backend.fireUdpDatagram("10.99.0.2:1", "10.99.0.1:53", "first".toByteArray())
        runCurrent()
        // After first flow closed, a fresh datagram from same peer
        // should result in a NEW flow object.
        backend.fireUdpDatagram("10.99.0.2:1", "10.99.0.1:53", "second".toByteArray())
        runCurrent()
        assertEquals(2, flows.size)
        assertNotSame(flows[0], flows[1])
    }

    @Test
    fun `listenUdp after close throws IllegalStateException`() = runTest {
        val backend = UdpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        endpoint.close()
        assertThrows(IllegalStateException::class.java) {
            endpoint.listenUdp(53, backgroundScope, { _, _ -> null }) { }
        }
    }

    @Test
    fun `flow channel overflow drops the oldest datagram (UDP-typical)`() = runTest {
        val backend = UdpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        val flowReady = CompletableDeferred<WgUdpFlow>()
        endpoint.listenUdp(
            port = 53,
            scope = backgroundScope,
            targetResolver = { _, _ -> InetSocketAddress("8.8.8.8", 53) },
            // The 5-second delay simulates a stuck consumer.  Under
            // virtual time this advances instantly; under wall-clock
            // it used to be wasteful.
            onFlow = { flow -> flowReady.complete(flow); delay(5_000) },
            flowChannelCapacity = 2,
        )
        // Fire 4 datagrams to a flow that won't drain — the
        // channel's DROP_OLDEST policy means we should keep the
        // *latest* 2 ('c' and 'd').
        backend.fireUdpDatagram("10.99.0.2:1", "10.99.0.1:53", "a".toByteArray())
        val flow = flowReady.await()
        backend.fireUdpDatagram("10.99.0.2:1", "10.99.0.1:53", "b".toByteArray())
        backend.fireUdpDatagram("10.99.0.2:1", "10.99.0.1:53", "c".toByteArray())
        backend.fireUdpDatagram("10.99.0.2:1", "10.99.0.1:53", "d".toByteArray())
        val first = flow.receive()!!
        val second = flow.receive()!!
        // Latest two. Order is preserved (FIFO of the survivors).
        assertEquals("c", String(first))
        assertEquals("d", String(second))
    }

    @Test
    fun `same-peer datagrams do NOT create new flows while the first is alive`() = runTest {
        val backend = UdpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        val flows = Collections.synchronizedList(mutableListOf<WgUdpFlow>())
        endpoint.listenUdp(
            port = 53,
            scope = backgroundScope,
            targetResolver = { _, _ -> InetSocketAddress("8.8.8.8", 53) },
            onFlow = { flow -> flows += flow; flow.receive(); flow.receive(); flow.close() },
        )
        backend.fireUdpDatagram("10.99.0.2:1", "10.99.0.1:53", "x".toByteArray())
        backend.fireUdpDatagram("10.99.0.2:1", "10.99.0.1:53", "y".toByteArray())
        runCurrent()
        assertEquals(1, flows.size)
    }

    /** Minimal backend fake whose [fireUdpDatagram] lets the test
     * trigger a datagram event from outside the listener. */
    private class UdpFakeBackend : WgBridgeBackend {
        val udpPorts = mutableListOf<Int>()
        val sink = RecordingSink()
        var udpReceiver: WgUdpReceiver? = null

        fun fireUdpDatagram(peer: String, listen: String, data: ByteArray) {
            val r = udpReceiver ?: error("no UDP listener registered")
            r.onDatagram(peer, listen, data)
        }
        override fun configureUapi(uapi: String) {}
        override fun listenTcp(port: Int, acceptor: WgTcpAcceptor) {
            throw NotImplementedError("not part of UDP fake")
        }
        override fun listenUdp(port: Int, receiver: WgUdpReceiver): WgUdpSink {
            udpPorts += port
            udpReceiver = receiver
            return sink
        }
        override fun setFdProtector(protector: WgFdProtector?) {}
        override fun close() {}
    }

    /** Records every sendTo for assertions; close() is a no-op. */
    private class RecordingSink : WgUdpSink {
        val sends = Collections.synchronizedList(mutableListOf<Pair<String, ByteArray>>())
        override fun sendTo(peerAddr: String, data: ByteArray) {
            sends += peerAddr to data.copyOf()
        }
        override fun close() {}
    }
}
