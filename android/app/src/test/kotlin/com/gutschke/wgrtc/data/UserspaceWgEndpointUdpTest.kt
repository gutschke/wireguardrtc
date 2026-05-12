package com.gutschke.wgrtc.data

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotSame
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.InetSocketAddress
import java.util.Collections
import java.util.concurrent.atomic.AtomicInteger

/**
 * Tests for [UserspaceWgEndpoint.listenUdp] — the per-peer demuxer
 * that turns the bridge's single-handler API into one
 * [WgUdpFlow] per (peerAddr) pair.
 */
class UserspaceWgEndpointUdpTest {

    private val listenerJob = SupervisorJob()
    private val listenerScope = CoroutineScope(Dispatchers.Default + listenerJob)

    @AfterEach fun tearDown() { listenerJob.cancel() }

    @Test
    fun `listenUdp registers with backend at the right port`() {
        val backend = UdpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        endpoint.listenUdp(53, listenerScope, { _, _ -> InetSocketAddress("8.8.8.8", 53) }) {}
        assertEquals(listOf(53), backend.udpPorts)
    }

    @Test
    fun `first datagram from new peer creates a flow`() = runBlocking<Unit> {
        val backend = UdpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        val seen = CompletableDeferred<WgUdpFlow>()
        endpoint.listenUdp(
            port = 53,
            scope = listenerScope,
            targetResolver = { _, _ -> InetSocketAddress("8.8.8.8", 53) },
            onFlow = { flow -> seen.complete(flow); flow.receive() /* keep open */; flow.close() },
        )
        backend.fireUdpDatagram("10.99.0.2:7777", "10.99.0.1:53", "hi".toByteArray())
        val flow = withTimeout(2_000) { seen.await() }
        assertEquals("10.99.0.2", flow.peerAddress.hostString)
        assertEquals(7777, flow.peerAddress.port)
        assertEquals(InetSocketAddress("8.8.8.8", 53), flow.targetAddress)
    }

    @Test
    fun `flow receive yields the datagrams routed to that peer`() = runBlocking<Unit> {
        val backend = UdpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        val received = Collections.synchronizedList(mutableListOf<String>())
        val flowReady = CompletableDeferred<WgUdpFlow>()
        endpoint.listenUdp(
            port = 53,
            scope = listenerScope,
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
        // Wait for the flow object to exist so subsequent datagrams
        // route to the same one (no race with the demux insert).
        val flow = withTimeout(2_000) { flowReady.await() }
        backend.fireUdpDatagram("10.99.0.2:1", "10.99.0.1:53", "two".toByteArray())
        backend.fireUdpDatagram("10.99.0.2:1", "10.99.0.1:53", "three".toByteArray())
        // Drain a moment to let the consumer flush.
        for (i in 0 until 50) {
            if (received.size >= 3) break
            delay(20)
        }
        flow.close()
        assertEquals(listOf("one", "two", "three"), received.toList())
    }

    @Test
    fun `datagrams from different peers create separate flows`() = runBlocking<Unit> {
        val backend = UdpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        val flowsSeen = Collections.synchronizedList(mutableListOf<WgUdpFlow>())
        endpoint.listenUdp(
            port = 53,
            scope = listenerScope,
            targetResolver = { _, _ -> InetSocketAddress("8.8.8.8", 53) },
            onFlow = { flow -> flowsSeen += flow; flow.receive(); flow.close() },
        )
        backend.fireUdpDatagram("10.99.0.2:1", "10.99.0.1:53", "a".toByteArray())
        backend.fireUdpDatagram("10.99.0.3:1", "10.99.0.1:53", "b".toByteArray())
        for (i in 0 until 50) {
            if (flowsSeen.size >= 2) break
            delay(20)
        }
        assertEquals(2, flowsSeen.size)
        assertNotSame(flowsSeen[0], flowsSeen[1])
        assertEquals("10.99.0.2", flowsSeen[0].peerAddress.hostString)
        assertEquals("10.99.0.3", flowsSeen[1].peerAddress.hostString)
    }

    @Test
    fun `null target drops the datagram silently`() = runBlocking<Unit> {
        val backend = UdpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        val flowCount = AtomicInteger(0)
        endpoint.listenUdp(
            port = 53,
            scope = listenerScope,
            targetResolver = { _, _ -> null },
            onFlow = { flowCount.incrementAndGet(); it.close() },
        )
        backend.fireUdpDatagram("10.99.0.2:1", "10.99.0.1:53", "drop me".toByteArray())
        delay(50)
        assertEquals(0, flowCount.get())
    }

    @Test
    fun `flow send routes back to sink with right peer`() = runBlocking<Unit> {
        val backend = UdpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        val flowReady = CompletableDeferred<WgUdpFlow>()
        endpoint.listenUdp(
            port = 53,
            scope = listenerScope,
            targetResolver = { _, _ -> InetSocketAddress("8.8.8.8", 53) },
            onFlow = { flow ->
                flowReady.complete(flow)
                flow.receive() // wait for incoming
                flow.send("reply".toByteArray())
                flow.close()
            },
        )
        backend.fireUdpDatagram("10.99.0.2:42", "10.99.0.1:53", "ping".toByteArray())
        val flow = withTimeout(2_000) { flowReady.await() }
        // Wait for the send.
        for (i in 0 until 50) {
            if (backend.sink.sends.isNotEmpty()) break
            delay(20)
        }
        assertEquals(1, backend.sink.sends.size)
        val (peer, data) = backend.sink.sends[0]
        assertEquals("10.99.0.2:42", peer)
        assertArrayEquals("reply".toByteArray(), data)
        // Suppress "flow unused" lint.
        assertEquals("10.99.0.2", flow.peerAddress.hostString)
    }

    @Test
    fun `flow is removed from demux when onFlow returns and closing reopens`() = runBlocking<Unit> {
        val backend = UdpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        val flows = Collections.synchronizedList(mutableListOf<WgUdpFlow>())
        endpoint.listenUdp(
            port = 53,
            scope = listenerScope,
            targetResolver = { _, _ -> InetSocketAddress("8.8.8.8", 53) },
            onFlow = { flow -> flows += flow; flow.receive(); flow.close() },
        )
        backend.fireUdpDatagram("10.99.0.2:1", "10.99.0.1:53", "first".toByteArray())
        // Wait for the first onFlow to start + consume the datagram + return.
        for (i in 0 until 50) {
            if (flows.size >= 1 && flows[0].receive() == null) break
            delay(20)
        }
        // After first flow closed, a fresh datagram from same peer
        // should result in a NEW flow object.
        backend.fireUdpDatagram("10.99.0.2:1", "10.99.0.1:53", "second".toByteArray())
        for (i in 0 until 50) {
            if (flows.size >= 2) break
            delay(20)
        }
        assertEquals(2, flows.size)
        assertNotSame(flows[0], flows[1])
    }

    @Test
    fun `listenUdp after close throws IllegalStateException`() {
        val backend = UdpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        endpoint.close()
        assertThrows(IllegalStateException::class.java) {
            endpoint.listenUdp(53, listenerScope, { _, _ -> null }) { }
        }
    }

    @Test
    fun `flow channel overflow drops the oldest datagram (UDP-typical)`() = runBlocking<Unit> {
        val backend = UdpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        val flowReady = CompletableDeferred<WgUdpFlow>()
        endpoint.listenUdp(
            port = 53,
            scope = listenerScope,
            targetResolver = { _, _ -> InetSocketAddress("8.8.8.8", 53) },
            onFlow = { flow -> flowReady.complete(flow); /* don't drain */ delay(5_000) },
            flowChannelCapacity = 2,
        )
        // Fire 4 datagrams to a flow that won't drain — the
        // channel's DROP_OLDEST policy means we should keep the
        // *latest* 2 ('c' and 'd').
        backend.fireUdpDatagram("10.99.0.2:1", "10.99.0.1:53", "a".toByteArray())
        val flow = withTimeout(2_000) { flowReady.await() }
        backend.fireUdpDatagram("10.99.0.2:1", "10.99.0.1:53", "b".toByteArray())
        backend.fireUdpDatagram("10.99.0.2:1", "10.99.0.1:53", "c".toByteArray())
        backend.fireUdpDatagram("10.99.0.2:1", "10.99.0.1:53", "d".toByteArray())
        // Cancel the dummy `delay(5_000)` and let the test consume.
        delay(50)
        val first = withTimeout(2_000) { flow.receive() }!!
        val second = withTimeout(2_000) { flow.receive() }!!
        // Latest two. Order is preserved (FIFO of the survivors).
        assertEquals("c", String(first))
        assertEquals("d", String(second))
    }

    @Test
    fun `same-peer datagrams do NOT create new flows while the first is alive`() = runBlocking<Unit> {
        val backend = UdpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        val flows = Collections.synchronizedList(mutableListOf<WgUdpFlow>())
        endpoint.listenUdp(
            port = 53,
            scope = listenerScope,
            targetResolver = { _, _ -> InetSocketAddress("8.8.8.8", 53) },
            onFlow = { flow -> flows += flow; flow.receive(); flow.receive(); flow.close() },
        )
        backend.fireUdpDatagram("10.99.0.2:1", "10.99.0.1:53", "x".toByteArray())
        backend.fireUdpDatagram("10.99.0.2:1", "10.99.0.1:53", "y".toByteArray())
        for (i in 0 until 50) {
            if (flows.size >= 1) break
            delay(20)
        }
        delay(80) // give the second datagram a chance to (incorrectly) spawn another flow
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
