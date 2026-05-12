package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.IOException
import java.net.InetSocketAddress
import java.util.concurrent.LinkedBlockingDeque
import java.util.concurrent.TimeUnit

class WgTcpHandleConnectionTest {

    @Test
    fun `read pumps bytes from handle to InputStream`() {
        val handle = FakeHandle().apply {
            queueRead("hello".toByteArray())
            queueEof()
        }
        val conn = WgTcpHandleConnection(handle, InetSocketAddress("1.2.3.4", 80))
        val out = ByteArray(8)
        val n = conn.reader.read(out)
        assertEquals(5, n)
        assertEquals("hello", String(out, 0, n))
        assertEquals(-1, conn.reader.read(out))
    }

    @Test
    fun `read with offset and length copies into the right slice`() {
        val handle = FakeHandle().apply {
            queueRead("XYZ".toByteArray())
            queueEof()
        }
        val conn = WgTcpHandleConnection(handle, InetSocketAddress("1.2.3.4", 80))
        val out = ByteArray(8) { '_'.code.toByte() }
        val n = conn.reader.read(out, 2, 3)
        assertEquals(3, n)
        assertEquals("__XYZ___", String(out))
    }

    @Test
    fun `read of single byte uses int return`() {
        val handle = FakeHandle().apply {
            queueRead(byteArrayOf(0xff.toByte()))
            queueEof()
        }
        val conn = WgTcpHandleConnection(handle, InetSocketAddress("1.2.3.4", 80))
        // 0xff must round-trip as 255, not -1 (the EOF sentinel).
        assertEquals(0xff, conn.reader.read())
        assertEquals(-1, conn.reader.read())
    }

    @Test
    fun `write pumps bytes from OutputStream to handle`() {
        val handle = FakeHandle()
        val conn = WgTcpHandleConnection(handle, InetSocketAddress("1.2.3.4", 80))
        conn.writer.write("abc".toByteArray())
        conn.writer.write("DEF".toByteArray(), 1, 2)
        // Each write goes through as one call to handle.write — we
        // don't buffer in the OutputStream because flush semantics
        // matter for interactive protocols.
        assertArrayEquals("abc".toByteArray(), handle.takeWrite())
        assertArrayEquals("EF".toByteArray(), handle.takeWrite())
    }

    @Test
    fun `single-byte write goes through to handle`() {
        val handle = FakeHandle()
        val conn = WgTcpHandleConnection(handle, InetSocketAddress("1.2.3.4", 80))
        conn.writer.write(0x42)
        assertArrayEquals(byteArrayOf(0x42), handle.takeWrite())
    }

    @Test
    fun `peerAddress comes from the handle string`() {
        val handle = FakeHandle(peerAddress ="10.99.0.2:54321")
        val conn = WgTcpHandleConnection(handle, InetSocketAddress("1.2.3.4", 80))
        assertEquals("10.99.0.2", conn.peerAddress.hostString)
        assertEquals(54321, conn.peerAddress.port)
    }

    @Test
    fun `peerAddress IPv6-shaped string parses safely`() {
        // Defensive — hole-punching is IPv4-only, but the parser
        // shouldn't blow up if the underlying Net ever returns
        // a v6-looking address.
        val handle = FakeHandle(peerAddress ="[fd00::1]:443")
        val conn = WgTcpHandleConnection(handle, InetSocketAddress("1.2.3.4", 80))
        assertEquals("fd00::1", conn.peerAddress.hostString)
        assertEquals(443, conn.peerAddress.port)
    }

    @Test
    fun `malformed peer address throws`() {
        val handle = FakeHandle(peerAddress ="no-colon-here")
        assertThrows(IOException::class.java) {
            WgTcpHandleConnection(handle, InetSocketAddress("1.2.3.4", 80))
        }
    }

    @Test
    fun `targetAddress is the constructor argument`() {
        val handle = FakeHandle()
        val target = InetSocketAddress("8.8.8.8", 53)
        val conn = WgTcpHandleConnection(handle, target)
        assertEquals(target, conn.targetAddress)
    }

    @Test
    fun `close propagates to handle`() {
        val handle = FakeHandle()
        val conn = WgTcpHandleConnection(handle, InetSocketAddress("1.2.3.4", 80))
        conn.close()
        assertTrue(handle.closed)
    }

    @Test
    fun `transport errors from read are not silently swallowed`() {
        val handle = FakeHandle().apply { queueReadError(IOException("rst")) }
        val conn = WgTcpHandleConnection(handle, InetSocketAddress("1.2.3.4", 80))
        assertThrows(IOException::class.java) { conn.reader.read(ByteArray(8)) }
    }

    /**
     * Fake [WgTcpHandle] that lets tests script the byte-stream
     * the handle returns and capture writes. Reads come from a
     * blocking deque so the same fake works for sequential or
     * concurrent tests.
     */
    private class FakeHandle(
        override val peerAddress: String = "10.99.0.2:54321",
        override val listenAddress: String = "10.99.0.1:8080",
    ) : WgTcpHandle {
        private sealed class ReadEvent {
            data class Bytes(val data: ByteArray) : ReadEvent()
            data object Eof : ReadEvent()
            data class Error(val cause: Exception) : ReadEvent()
        }

        private val readQueue = LinkedBlockingDeque<ReadEvent>()
        private val writes = LinkedBlockingDeque<ByteArray>()
        @Volatile var closed: Boolean = false

        fun queueRead(data: ByteArray) { readQueue.put(ReadEvent.Bytes(data)) }
        fun queueEof() { readQueue.put(ReadEvent.Eof) }
        fun queueReadError(e: Exception) { readQueue.put(ReadEvent.Error(e)) }
        fun takeWrite(): ByteArray = writes.poll(2, TimeUnit.SECONDS)
            ?: error("expected a write, got none")

        override fun read(buf: ByteArray): Int {
            val ev = readQueue.poll(2, TimeUnit.SECONDS)
                ?: error("read called with no scripted event")
            return when (ev) {
                is ReadEvent.Bytes -> {
                    val n = minOf(buf.size, ev.data.size)
                    System.arraycopy(ev.data, 0, buf, 0, n)
                    if (ev.data.size > n) {
                        // Re-queue the leftovers so a smaller read
                        // size doesn't lose bytes.
                        readQueue.addFirst(
                            ReadEvent.Bytes(ev.data.copyOfRange(n, ev.data.size))
                        )
                    }
                    n
                }
                ReadEvent.Eof -> -1
                is ReadEvent.Error -> throw ev.cause
            }
        }

        override fun write(buf: ByteArray) { writes.put(buf.copyOf()) }
        override fun close() { closed = true }
    }
}
