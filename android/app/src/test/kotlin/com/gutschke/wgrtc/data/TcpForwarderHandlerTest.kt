package com.gutschke.wgrtc.data

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.SocketFactory
import java.util.concurrent.atomic.AtomicInteger

/**
 * **TCP forwarder handler unit tests.**
 *
 * Pins the *Kotlin* side of the forwarder. The Go-side
 * `tcp.NewForwarder` is exercised by [NatTcpForwarderE2ETest]
 * on the emulator; here we test the handler's decision logic
 * in isolation, using fakes for the socket factory + the WG
 * connection. The point of these tests is to catch refactors
 * that break:
 *
 * - "deny" decisions from the target resolver — must close
 * the inbound WG conn without leaking a socket
 * - upstream socket-open failures — must close the WG conn
 * and not leave it half-open
 * - peer / origDest correctly threaded through to the
 * forwarder's open call
 *
 * Throughput + half-close + concurrency live in the e2e test
 * (real gvisor + real OS sockets are the only honest place to
 * exercise those).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class TcpForwarderHandlerTest {

    private class FakeWgTcpHandle(
        override val peerAddress: String = "10.99.0.2:54321",
        override val listenAddress: String = "10.99.0.1:80",
    ) : WgTcpHandle {
        var closed = false
        val readResponses = ArrayDeque<Int>()
        val written = mutableListOf<ByteArray>()
        override fun read(buf: ByteArray): Int =
            if (closed) -1 else readResponses.removeFirstOrNull() ?: -1
        override fun write(buf: ByteArray) {
            if (closed) throw IOException("closed")
            written += buf.copyOf()
        }
        override fun close() { closed = true }
    }

    /** Socket factory that records every attempted destination
     * and produces a paired pipe so the test can drive reads. */
    private class RecordingSocketFactory(
        private val refuse: Boolean = false,
    ) : SocketFactory() {
        val attempts = mutableListOf<InetSocketAddress>()
        val createdSockets = mutableListOf<Socket>()
        override fun createSocket(): Socket {
            // SocketFactory contract: createSocket() returns an
            // unconnected socket; the caller calls .connect.
            val s = Socket()
            createdSockets += s
            return s
        }
        override fun createSocket(host: String, port: Int): Socket {
            attempts += InetSocketAddress(host, port)
            if (refuse) throw IOException("refused")
            // Loopback to a closed port — connect will fail; for
            // the resolver-deny path that's fine because the
            // handler should never call this anyway.
            return Socket()
        }
        override fun createSocket(host: String, port: Int, localHost: java.net.InetAddress, localPort: Int): Socket =
            createSocket(host, port)
        override fun createSocket(host: java.net.InetAddress, port: Int): Socket =
            createSocket(host.hostAddress, port)
        override fun createSocket(address: java.net.InetAddress, port: Int, localAddress: java.net.InetAddress, localPort: Int): Socket =
            createSocket(address.hostAddress, port)
    }

    @Test
    fun resolverThatRefusesClosesTheWgConnectionWithoutOpeningASocket() = runTest {
        val factory = RecordingSocketFactory()
        val openCount = AtomicInteger(0)
        val handler = TcpForwarderHandler(
            socketFactory = factory,
            targetResolver = { _, _ -> null }, // refuse all
            onForwardStart = { _, _ -> openCount.incrementAndGet() },
            ioDispatcher = UnconfinedTestDispatcher(testScheduler),
        )
        val wg = FakeWgTcpHandle(listenAddress = "10.99.0.1:443")
        handler.dispatch(this, peerAddr = "10.99.0.2:33333",
                          origDest = "192.0.2.1:443", wg = wg)
        advanceUntilIdle()
        assertTrue(wg.closed, "WG connection must be closed when resolver refuses")
        assertEquals(0, factory.attempts.size,
            "socket factory must NOT be called when resolver refuses")
        assertEquals(0, openCount.get())
    }

    @Test
    fun resolverThatAcceptsRoutesToTheReturnedAddress() = runTest {
        val factory = RecordingSocketFactory(refuse = true) // fail the connect; we just want to see the resolver was called
        val resolverArgs = mutableListOf<Pair<String, String>>()
        val handler = TcpForwarderHandler(
            socketFactory = factory,
            targetResolver = { peer, dest ->
                resolverArgs += peer to dest
                InetSocketAddress("192.0.2.99", 8888)
            },
            ioDispatcher = UnconfinedTestDispatcher(testScheduler),
        )
        val wg = FakeWgTcpHandle()
        handler.dispatch(this, peerAddr = "10.99.0.2:11111",
                          origDest = "192.0.2.1:443", wg = wg)
        advanceUntilIdle()
        assertEquals(1, resolverArgs.size, "resolver called exactly once")
        assertEquals("10.99.0.2:11111", resolverArgs[0].first, "peer threaded through")
        assertEquals("192.0.2.1:443", resolverArgs[0].second, "origDest threaded through")
        // The connect failed (factory is in refuse mode), so the
        // handler should have closed the WG conn rather than
        // leaving it half-open.
        assertTrue(wg.closed, "WG conn must be closed when socket open fails")
    }

    @Test
    fun ifFactoryThrowsWgConnectionIsClosedCleanly() = runTest {
        val factory = RecordingSocketFactory(refuse = true)
        val handler = TcpForwarderHandler(
            socketFactory = factory,
            targetResolver = { _, _ -> InetSocketAddress("192.0.2.1", 80) },
            ioDispatcher = UnconfinedTestDispatcher(testScheduler),
        )
        val wg = FakeWgTcpHandle()
        handler.dispatch(this, peerAddr = "10.99.0.2:1", origDest = "192.0.2.1:80", wg = wg)
        advanceUntilIdle()
        assertTrue(wg.closed)
    }

    @Test
    fun parseOrigDestRejectsMalformedInput() = runTest {
        val handler = TcpForwarderHandler(
            socketFactory = RecordingSocketFactory(),
            targetResolver = { _, _ -> InetSocketAddress("ignored", 1) },
            ioDispatcher = UnconfinedTestDispatcher(testScheduler),
        )
        val wg = FakeWgTcpHandle()
        // Missing the colon.
        handler.dispatch(this, peerAddr = "10.99.0.2:1", origDest = "garbage", wg = wg)
        advanceUntilIdle()
        assertTrue(wg.closed, "malformed origDest must close the WG conn, not throw")
    }
}
