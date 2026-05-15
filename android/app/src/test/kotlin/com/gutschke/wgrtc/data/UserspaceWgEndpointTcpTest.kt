package com.gutschke.wgrtc.data

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.IOException
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicInteger

/**
 * Tests for [UserspaceWgEndpoint.listenTcp] wiring.
 *
 * Uses [runTest] with virtual time so the test scheduler controls
 * dispatch — no real wall clock, no [kotlinx.coroutines.Dispatchers.Default].  The
 * listener scope is `backgroundScope`, which is auto-cancelled
 * when the test finishes, so there's no need for a manual
 * `SupervisorJob` + `tearDown`.  Bullet-proofs the suite against
 * host-CPU starvation that previously caused intermittent
 * `TimeoutCancellationException` failures (FLAKE task).
 */
class UserspaceWgEndpointTcpTest {

    @Test
    fun `listenTcp registers with backend at the right port`() {
        val backend = TcpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        // No coroutine launches here, so this test doesn't need
        // runTest — but use the same backgroundScope shape as the
        // other tests for consistency.
        runTest {
            endpoint.listenTcp(
                8080, backgroundScope,
                { _, _ -> InetSocketAddress("9.9.9.9", 80) },
            ) {}
            assertEquals(listOf(8080), backend.tcpPorts)
        }
    }

    @Test
    fun `accepted connection is wrapped and onConnection invoked`() = runTest {
        val backend = TcpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        val seen = CompletableDeferred<WgTcpConnection>()
        endpoint.listenTcp(
            port = 8080,
            scope = backgroundScope,
            targetResolver = { _, _ -> InetSocketAddress("9.9.9.9", 80) },
            onConnection = { conn -> seen.complete(conn) },
        )
        backend.fireTcpAccept(
            peer = "10.99.0.2:54321",
            listen = "10.99.0.1:8080",
            handle = ScriptedHandle(),
        )
        val conn = seen.await()
        assertEquals("10.99.0.2", conn.peerAddress.hostString)
        assertEquals(54321, conn.peerAddress.port)
        assertEquals(InetSocketAddress("9.9.9.9", 80), conn.targetAddress)
    }

    @Test
    fun `null target closes the handle and skips onConnection`() = runTest {
        val backend = TcpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        val handle = ScriptedHandle()
        val invoked = AtomicInteger(0)
        endpoint.listenTcp(
            port = 8080,
            scope = backgroundScope,
            targetResolver = { _, _ -> null },
            onConnection = { invoked.incrementAndGet() },
        )
        backend.fireTcpAccept("10.99.0.2:1", "10.99.0.1:8080", handle)
        runCurrent() // flush any spurious onConnection launch
        assertTrue(handle.closed)
        assertEquals(0, invoked.get())
    }

    @Test
    fun `target resolver receives the peer and listen addresses verbatim`() = runTest {
        val backend = TcpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        val resolverArgs = CompletableDeferred<Pair<String, String>>()
        endpoint.listenTcp(
            port = 8080,
            scope = backgroundScope,
            targetResolver = { peer, listen ->
                resolverArgs.complete(peer to listen)
                InetSocketAddress("9.9.9.9", 80)
            },
            onConnection = { /* no-op */ },
        )
        backend.fireTcpAccept(
            peer = "10.99.0.2:54321",
            listen = "10.99.0.1:8080",
            handle = ScriptedHandle(),
        )
        val (peer, listen) = resolverArgs.await()
        assertEquals("10.99.0.2:54321", peer)
        assertEquals("10.99.0.1:8080", listen)
    }

    @Test
    fun `forwarder errors are caught and don't kill the listener`() = runTest {
        val backend = TcpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        val secondCallSeen = CompletableDeferred<Unit>()
        var first = true
        endpoint.listenTcp(
            port = 8080,
            scope = backgroundScope,
            targetResolver = { _, _ -> InetSocketAddress("9.9.9.9", 80) },
            onConnection = {
                if (first) { first = false; throw IOException("forwarder boom") }
                else secondCallSeen.complete(Unit)
            },
        )
        backend.fireTcpAccept("10.99.0.2:1", "10.99.0.1:8080", ScriptedHandle())
        // Second accept after the first one's onConnection threw —
        // proves the listener is still routing.
        backend.fireTcpAccept("10.99.0.3:1", "10.99.0.1:8080", ScriptedHandle())
        secondCallSeen.await()
    }

    @Test
    fun `connection is closed after onConnection completes`() = runTest {
        val backend = TcpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        val handle = ScriptedHandle()
        endpoint.listenTcp(
            port = 8080,
            scope = backgroundScope,
            targetResolver = { _, _ -> InetSocketAddress("9.9.9.9", 80) },
            onConnection = { /* finishes immediately */ },
        )
        backend.fireTcpAccept("10.99.0.2:1", "10.99.0.1:8080", handle)
        runCurrent()
        assertTrue(handle.closed)
    }

    @Test
    fun `listenTcp after close throws IllegalStateException`() = runTest {
        val backend = TcpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        endpoint.close()
        assertThrows(IllegalStateException::class.java) {
            endpoint.listenTcp(
                port = 8080,
                scope = backgroundScope,
                targetResolver = { _, _ -> null },
                onConnection = { },
            )
        }
    }

    @Test
    fun `wrapped connection round-trips bytes via the underlying handle`() = runTest {
        val backend = TcpFakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        val handle = ScriptedHandle().apply {
            queueRead("hi".toByteArray())
            queueEof()
        }
        val readBack = CompletableDeferred<String?>()
        endpoint.listenTcp(
            port = 8080,
            scope = backgroundScope,
            targetResolver = { _, _ -> InetSocketAddress("9.9.9.9", 80) },
            onConnection = { conn ->
                val buf = ByteArray(8)
                val n = conn.reader.read(buf)
                val text = if (n < 0) null else String(buf, 0, n)
                conn.writer.write("ack".toByteArray())
                readBack.complete(text)
            },
        )
        backend.fireTcpAccept("10.99.0.2:1", "10.99.0.1:8080", handle)
        val v = readBack.await()
        assertEquals("hi", v)
        assertArrayEquals("ack".toByteArray(), handle.takeWrite())
    }

    /** Backend fake whose [fireTcpAccept] lets the test trigger an
     * accept event from outside the listener. */
    private class TcpFakeBackend : WgBridgeBackend {
        val tcpPorts = mutableListOf<Int>()
        var tcpAcceptor: WgTcpAcceptor? = null

        fun fireTcpAccept(peer: String, listen: String, handle: ScriptedHandle) {
            val a = tcpAcceptor ?: error("no listener registered")
            a.onAccept(peer, listen, handle)
        }
        override fun configureUapi(uapi: String) {}
        override fun listenTcp(port: Int, acceptor: WgTcpAcceptor) {
            tcpPorts += port
            tcpAcceptor = acceptor
        }
        override fun listenUdp(port: Int, receiver: WgUdpReceiver): WgUdpSink =
            throw NotImplementedError("not part of TCP fake")
        override fun setFdProtector(protector: WgFdProtector?) {}
        override fun close() {}
    }

    /** Narrow scripted handle for wiring-level tests; the full
     * [WgTcpHandleConnectionTest.FakeHandle] is overkill here. */
    private class ScriptedHandle(
        override val peerAddress: String = "10.99.0.2:54321",
        override val listenAddress: String = "10.99.0.1:8080",
    ) : WgTcpHandle {
        private val reads = ArrayDeque<ByteArray?>()
        private val writes = mutableListOf<ByteArray>()
        @Volatile var closed = false

        fun queueRead(b: ByteArray) { synchronized(reads) { reads.addLast(b) } }
        fun queueEof() { synchronized(reads) { reads.addLast(null) } }
        fun takeWrite(): ByteArray = synchronized(writes) {
            check(writes.isNotEmpty()) { "expected a write, got none" }
            writes.removeAt(0)
        }

        override fun read(buf: ByteArray): Int = synchronized(reads) {
            val ev = reads.removeFirstOrNull() ?: error("no scripted read")
            if (ev == null) return -1
            val n = minOf(buf.size, ev.size)
            System.arraycopy(ev, 0, buf, 0, n)
            n
        }
        override fun write(buf: ByteArray) { synchronized(writes) { writes += buf.copyOf() } }
        override fun close() { closed = true }
    }
}
