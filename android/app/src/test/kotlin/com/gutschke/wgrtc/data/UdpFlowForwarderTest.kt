package com.gutschke.wgrtc.data

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Unit tests for [UdpFlowForwarder] using a localhost UDP echo
 * server as the external target. The "WG peer" side is modeled
 * as a [FakeWgUdpFlow] backed by Channels — bytes a test writes
 * to `inbound` are delivered to the forwarder's `receive()`, and
 * bytes the forwarder sends via `send()` end up in `outbound`
 * for the test to assert on.
 */
class UdpFlowForwarderTest {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @AfterEach fun tearDownScope() { scope.cancel() }

    @Test fun `single datagram round-trips through forwarder`() = runBlocking<Unit> {
        val echo = UdpEchoServer().also { it.start() }
        try {
            val flow = FakeWgUdpFlow(
                peerAddress = InetSocketAddress("10.99.0.2", 12345),
                targetAddress = echo.address,
            )
            val job = scope.launch {
                UdpFlowForwarder(idleTtlMs = 5_000L).forward(flow)
            }
            // Peer sends a datagram via WG.
            flow.injectInbound("ping".toByteArray())
            // Echo server bounces it back; forwarder sends back via flow.
            val reply = flow.awaitOutbound(2000)
            assertNotNull(reply)
            assertEquals("ping", String(reply!!))
            flow.close()
            withTimeoutOrNull(2000) { job.join() }
        } finally {
            echo.stop()
        }
    }

    @Test fun `multiple datagrams reuse the same external socket`() = runBlocking<Unit> {
        val echo = UdpEchoServer().also { it.start() }
        try {
            val flow = FakeWgUdpFlow(
                peerAddress = InetSocketAddress("10.99.0.2", 5555),
                targetAddress = echo.address,
            )
            val job = scope.launch {
                UdpFlowForwarder(idleTtlMs = 5_000L).forward(flow)
            }
            flow.injectInbound("one".toByteArray())
            assertEquals("one", String(flow.awaitOutbound(2000)!!))
            flow.injectInbound("two".toByteArray())
            assertEquals("two", String(flow.awaitOutbound(2000)!!))
            flow.injectInbound("three".toByteArray())
            assertEquals("three", String(flow.awaitOutbound(2000)!!))
            // Echo server should have only seen ONE source-port (proves we
            // reused the socket).
            assertEquals(1, echo.distinctSources.size,
                "expected one external source port, got ${echo.distinctSources}")
            flow.close()
            withTimeoutOrNull(2000) { job.join() }
        } finally {
            echo.stop()
        }
    }

    @Test fun `idle TTL closes the flow`() = runBlocking<Unit> {
        val echo = UdpEchoServer().also { it.start() }
        try {
            val flow = FakeWgUdpFlow(
                peerAddress = InetSocketAddress("10.99.0.2", 7777),
                targetAddress = echo.address,
            )
            val job = scope.launch {
                UdpFlowForwarder(idleTtlMs = 250L).forward(flow)
            }
            flow.injectInbound("hi".toByteArray())
            assertEquals("hi", String(flow.awaitOutbound(2000)!!))
            // Wait past the idle TTL; the forwarder should close + return.
            val finished = withTimeoutOrNull(3000) { job.join(); true } ?: false
            assertTrue(finished, "forwarder should self-close on idle TTL")
            // Subsequent send via flow should observe the closed state.
            assertTrue(flow.closed, "flow.close() should have been called")
        } finally {
            echo.stop()
        }
    }

    @Test fun `cancel cleans up external socket`() = runBlocking<Unit> {
        val echo = UdpEchoServer().also { it.start() }
        try {
            val flow = FakeWgUdpFlow(
                peerAddress = InetSocketAddress("10.99.0.2", 9999),
                targetAddress = echo.address,
            )
            val job = scope.launch {
                UdpFlowForwarder(idleTtlMs = 60_000L).forward(flow)
            }
            // First datagram so the forwarder has bound an external socket.
            flow.injectInbound("hello".toByteArray())
            flow.awaitOutbound(2000)
            // Cancel the forwarder; flow should be closed.
            job.cancel()
            withTimeoutOrNull(2000) { job.join() }
            assertTrue(flow.closed)
        } finally {
            echo.stop()
        }
    }

    @Test fun `flow close-from-peer terminates forwarder`() = runBlocking<Unit> {
        val echo = UdpEchoServer().also { it.start() }
        try {
            val flow = FakeWgUdpFlow(
                peerAddress = InetSocketAddress("10.99.0.2", 1234),
                targetAddress = echo.address,
            )
            val job = scope.launch {
                UdpFlowForwarder(idleTtlMs = 60_000L).forward(flow)
            }
            flow.injectInbound("abc".toByteArray())
            assertEquals("abc", String(flow.awaitOutbound(2000)!!))
            // Peer-side close (e.g. the WG peer disconnected).
            flow.close()
            // Forwarder should detect via receive() returning null and exit.
            val finished = withTimeoutOrNull(3000) { job.join(); true } ?: false
            assertTrue(finished, "forwarder should complete on peer close")
        } finally {
            echo.stop()
        }
    }

    // ─── helpers ────────────────────────────────────────────────────────

    /** UDP echo server that records which source ports it sees so
     * tests can assert socket-reuse behaviour. */
    private class UdpEchoServer {
        private val sock = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val address: InetSocketAddress get() = InetSocketAddress("127.0.0.1", sock.localPort)
        val distinctSources: MutableSet<Int> = java.util.Collections.synchronizedSet(mutableSetOf())
        @Volatile private var stopped = false
        private val thread = Thread {
            val buf = ByteArray(2048)
            while (!stopped) {
                try {
                    val pkt = DatagramPacket(buf, buf.size)
                    sock.receive(pkt)
                    distinctSources += pkt.port
                    // Echo: send the same data back to the source.
                    sock.send(DatagramPacket(pkt.data, pkt.length, pkt.address, pkt.port))
                } catch (_: Exception) { return@Thread }
            }
        }
        fun start() { thread.start() }
        fun stop() { stopped = true; try { sock.close() } catch (_: Exception) {} }
    }

    private class FakeWgUdpFlow(
        override val peerAddress: InetSocketAddress,
        override val targetAddress: InetSocketAddress,
    ) : WgUdpFlow {
        private val inbound = Channel<ByteArray>(Channel.UNLIMITED)
        private val outbound = ConcurrentLinkedQueue<ByteArray>()
        @Volatile var closed: Boolean = false; private set

        /** Test-side: inject a datagram from the WG peer. */
        suspend fun injectInbound(data: ByteArray) { inbound.send(data) }

        /** Test-side: poll for the next datagram the forwarder sent
         * back to the peer. Returns null on timeout. */
        suspend fun awaitOutbound(timeoutMs: Long): ByteArray? {
            val deadline = System.currentTimeMillis() + timeoutMs
            while (System.currentTimeMillis() < deadline) {
                val data = outbound.poll()
                if (data != null) return data
                delay(20)
            }
            return null
        }

        // ── WgUdpFlow ──
        override suspend fun receive(): ByteArray? {
            if (closed) return null
            // Block on inbound; null when channel is closed.
            return inbound.receiveCatching().getOrNull()
        }
        override suspend fun send(data: ByteArray) { outbound.add(data) }
        override fun close() {
            if (closed) return
            closed = true
            inbound.close()
        }
    }
}
