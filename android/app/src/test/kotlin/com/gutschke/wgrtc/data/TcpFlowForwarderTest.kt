package com.gutschke.wgrtc.data

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket

/**
 * Pure-JVM unit tests for [TcpFlowForwarder]. We model the
 * userspace WG endpoint side with a [PipedInputStream] +
 * [PipedOutputStream] pair (a [FakeWgTcpConnection]) — bytes the
 * "WG peer" wrote appear on the forwarder's input, and bytes the
 * forwarder writes back appear on the "WG peer" output.
 *
 * The external-target side uses a real localhost [ServerSocket],
 * so we exercise real Java NIO under the forwarder. This catches
 * subtle bugs (half-close semantics, buffering) that a pure
 * fake-against-fake test wouldn't.
 */
class TcpFlowForwarderTest {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @AfterEach fun tearDownScope() {
        scope.cancel()
    }

    @Test fun `bytes flow from WG peer to external target`() = runBlocking<Unit> {
        val server = EchoServer().also { it.start() }
        try {
            val (conn, peerInput, peerOutput) = newFakeConnection(server.address)

            val job = scope.launch {
                TcpFlowForwarder().forward(conn, server.address)
            }

            // "WG peer" sends a payload.
            peerOutput.write("HELLO-WORLD".toByteArray())
            peerOutput.flush()

            // Echo server returns it; forwarder pipes it back.
            val reply = readNBytes(peerInput, "HELLO-WORLD".length)
            assertEquals("HELLO-WORLD", String(reply))

            conn.close()
            withTimeoutOrNull(2000) { job.join() }
        } finally {
            server.stop()
        }
    }

    @Test fun `bidirectional bytes flow correctly`() = runBlocking<Unit> {
        // Run an "uppercase echo" server: it returns input transformed.
        val server = TransformServer { it.uppercase() }.also { it.start() }
        try {
            val (conn, peerInput, peerOutput) = newFakeConnection(server.address)

            val job = scope.launch {
                TcpFlowForwarder().forward(conn, server.address)
            }

            peerOutput.write("hello".toByteArray())
            peerOutput.flush()
            val reply1 = readNBytes(peerInput, 5)
            assertEquals("HELLO", String(reply1))

            peerOutput.write("world".toByteArray())
            peerOutput.flush()
            val reply2 = readNBytes(peerInput, 5)
            assertEquals("WORLD", String(reply2))

            conn.close()
            withTimeoutOrNull(2000) { job.join() }
        } finally {
            server.stop()
        }
    }

    @Test fun `EOF from WG peer triggers clean shutdown`() = runBlocking<Unit> {
        val server = EchoServer().also { it.start() }
        try {
            val (conn, peerInput, peerOutput) = newFakeConnection(server.address)

            val job = scope.launch {
                TcpFlowForwarder().forward(conn, server.address)
            }

            peerOutput.write("abc".toByteArray())
            peerOutput.flush()
            // Half-close: WG peer closes its write side.
            peerOutput.close()

            // Forwarder should pump the "abc" through then complete.
            val reply = readNBytes(peerInput, 3)
            assertEquals("abc", String(reply))

            // The forwarder should detect peer EOF + finish.
            val finished = withTimeoutOrNull(3000) { job.join(); true } ?: false
            assertTrue(finished, "forwarder should complete on peer EOF")
        } finally {
            server.stop()
        }
    }

    @Test fun `external connect-refused is reported as IOException`() = runBlocking<Unit> {
        // Pick a port that's almost certainly closed.
        val deadAddr = InetSocketAddress("127.0.0.1", 1) // port 1 = tcpmux, almost never running
        val (conn, _, _) = newFakeConnection(deadAddr)

        val ex = try {
            TcpFlowForwarder().forward(conn, deadAddr)
            null
        } catch (t: Throwable) { t }
        assertNotNull(ex)
        // Either ConnectException (refused) or NoRouteToHost — both IOException subtypes.
        assertTrue(ex is IOException, "expected IOException, got ${ex?.javaClass}")
    }

    @Test fun `cancellation cleans up sockets`() = runBlocking<Unit> {
        // Long-running connection that doesn't echo.
        val server = SilentServer().also { it.start() }
        try {
            val (conn, _, peerOutput) = newFakeConnection(server.address)
            val job = scope.launch {
                TcpFlowForwarder().forward(conn, server.address)
            }
            // Wait until the forwarder has connected to the silent server.
            withTimeoutOrNull(2000) {
                while (server.connectionCount == 0) delay(20)
            }
            assertEquals(1, server.connectionCount)

            // Cancel; the forwarder should release both sides.
            job.cancel()
            withTimeoutOrNull(3000) { job.join() }

            // The peer side write should now error (forwarder closed input).
            // We don't assert that directly because Piped streams have
            // delicate semantics; we instead assert the server-side
            // connection has been closed.
            withTimeoutOrNull(2000) {
                while (!server.lastConnectionClosed) delay(20)
            }
            assertTrue(server.lastConnectionClosed,
                "external socket should be closed when forwarder cancels")
        } finally {
            server.stop()
        }
    }

    @Test fun `large payload streams without buffering whole thing`() = runBlocking<Unit> {
        val server = EchoServer().also { it.start() }
        try {
            val (conn, peerInput, peerOutput) = newFakeConnection(server.address)
            val job = scope.launch {
                TcpFlowForwarder(bufferSize = 1024).forward(conn, server.address)
            }

            // 1 MiB of pseudo-random bytes (deterministic).
            val payload = ByteArray(1 shl 20) { (it and 0xFF).toByte() }
            scope.launch {
                peerOutput.write(payload)
                peerOutput.flush()
                peerOutput.close()
            }

            val received = ByteArray(payload.size)
            var off = 0
            while (off < received.size) {
                val n = peerInput.read(received, off, received.size - off)
                if (n <= 0) break
                off += n
            }
            assertEquals(payload.size, off, "must receive full payload")
            assertArrayEquals(payload, received)

            withTimeoutOrNull(5000) { job.join() }
        } finally {
            server.stop()
        }
    }

    // ─── helpers ────────────────────────────────────────────────

    /** Build a fake connection pair. Returns the WgTcpConnection
     * (which the forwarder consumes) plus the streams the test code
     * uses to act as the WG peer. */
    private fun newFakeConnection(target: InetSocketAddress): Triple<WgTcpConnection, InputStream, OutputStream> {
        // Forwarder reads from connToForwarder.input (the "WG peer
        // wrote this"), writes to connToForwarder.output (the "WG peer
        // will read this").
        val forwarderInputPipe = PipedInputStream(64 * 1024)
        val peerOutput = PipedOutputStream(forwarderInputPipe)
        val forwarderOutputPipe = PipedOutputStream()
        val peerInput = PipedInputStream(forwarderOutputPipe, 64 * 1024)
        val conn = FakeWgTcpConnection(
            reader = forwarderInputPipe,
            writer = forwarderOutputPipe,
            peerAddress = InetSocketAddress("10.99.0.2", 12345),
            targetAddress = target,
        )
        return Triple(conn, peerInput, peerOutput)
    }

    private fun readNBytes(input: InputStream, n: Int): ByteArray {
        val out = ByteArray(n)
        var off = 0
        while (off < n) {
            val read = input.read(out, off, n - off)
            if (read <= 0) break
            off += read
        }
        return out.copyOf(off)
    }

    /** Minimal echo server on a localhost ephemeral port. */
    private class EchoServer {
        private val server = ServerSocket(0, 50, java.net.InetAddress.getByName("127.0.0.1"))
        val address: InetSocketAddress get() = InetSocketAddress("127.0.0.1", server.localPort)
        @Volatile private var stopped = false
        private val thread = Thread {
            while (!stopped) {
                try {
                    val s = server.accept()
                    Thread {
                        try {
                            s.use {
                                val buf = ByteArray(4096)
                                while (true) {
                                    val n = s.getInputStream().read(buf)
                                    if (n <= 0) break
                                    s.getOutputStream().write(buf, 0, n)
                                    s.getOutputStream().flush()
                                }
                            }
                        } catch (_: Exception) {}
                    }.start()
                } catch (_: Exception) { return@Thread }
            }
        }
        fun start() { thread.start() }
        fun stop() { stopped = true; try { server.close() } catch (_: Exception) {} }
    }

    /** Echo server that transforms each chunk before echoing. */
    private class TransformServer(val transform: (String) -> String) {
        private val server = ServerSocket(0, 50, java.net.InetAddress.getByName("127.0.0.1"))
        val address: InetSocketAddress get() = InetSocketAddress("127.0.0.1", server.localPort)
        @Volatile private var stopped = false
        private val thread = Thread {
            while (!stopped) {
                try {
                    val s = server.accept()
                    Thread {
                        try {
                            s.use {
                                val buf = ByteArray(4096)
                                while (true) {
                                    val n = s.getInputStream().read(buf)
                                    if (n <= 0) break
                                    val out = transform(String(buf, 0, n)).toByteArray()
                                    s.getOutputStream().write(out)
                                    s.getOutputStream().flush()
                                }
                            }
                        } catch (_: Exception) {}
                    }.start()
                } catch (_: Exception) { return@Thread }
            }
        }
        fun start() { thread.start() }
        fun stop() { stopped = true; try { server.close() } catch (_: Exception) {} }
    }

    /** Server that accepts but never sends. */
    private class SilentServer {
        private val server = ServerSocket(0, 50, java.net.InetAddress.getByName("127.0.0.1"))
        val address: InetSocketAddress get() = InetSocketAddress("127.0.0.1", server.localPort)
        @Volatile var connectionCount: Int = 0
        @Volatile var lastConnectionClosed: Boolean = false
        private var lastSocket: Socket? = null
        @Volatile private var stopped = false
        private val thread = Thread {
            while (!stopped) {
                try {
                    val s = server.accept()
                    connectionCount += 1
                    lastSocket = s
                    Thread {
                        try {
                            // Block until the peer closes.
                            s.getInputStream().read()
                        } catch (_: Exception) {}
                        finally {
                            lastConnectionClosed = true
                            try { s.close() } catch (_: Exception) {}
                        }
                    }.start()
                } catch (_: Exception) { return@Thread }
            }
        }
        fun start() { thread.start() }
        fun stop() {
            stopped = true
            try { lastSocket?.close() } catch (_: Exception) {}
            try { server.close() } catch (_: Exception) {}
        }
    }

    /** Test seam. Production code wraps a wgbridge-supplied accepted
     * connection; tests wrap a piped pair. */
    private class FakeWgTcpConnection(
        override val reader: InputStream,
        override val writer: OutputStream,
        override val peerAddress: InetSocketAddress,
        override val targetAddress: InetSocketAddress,
    ) : WgTcpConnection {
        override fun close() {
            try { reader.close() } catch (_: Exception) {}
            try { writer.close() } catch (_: Exception) {}
        }
    }
}
