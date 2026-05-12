package com.gutschke.wgrtc.data

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.SocketFactory

/**
 * Pump bytes between a [WgTcpConnection] (a connection accepted by
 * our userspace WG endpoint via wgbridge / netstack) and a regular
 * outbound [Socket]. This is the heart: the
 * forwarder makes the WG peer's traffic emerge from the phone's app
 * uid as if the phone itself sent it.
 *
 * Two coroutines run concurrently:
 * - "outbound": copy [WgTcpConnection.reader] → [Socket]'s output
 * - "inbound": copy [Socket]'s input → [WgTcpConnection.writer]
 *
 * Returns when both directions have completed. Half-close is
 * propagated (peer closes write side → we close socket's write
 * side; socket closes write side → we close peer write side).
 *
 * Errors propagate: a failed connect to [externalTarget] throws
 * [IOException]; runtime stream errors close both sides and let
 * [forward] return normally (the peer sees EOF).
 *
 * Cancellation: cancelling the calling coroutine's job cleanly
 * tears down both sockets.
 */
class TcpFlowForwarder(
    private val socketFactory: SocketFactory = SocketFactory.getDefault(),
    private val bufferSize: Int = 8 * 1024,
    /** Connect timeout in ms. Wide enough for cellular RTT but
     * short enough that a wrong dst doesn't hang indefinitely. */
    private val connectTimeoutMs: Int = 10_000,
    /** Dispatcher for the blocking byte-pumps. Defaults to the
     * shared host-mode forwarder cached pool so per-flow thread
     * pinning can't exhaust `Dispatchers.IO`. See
     * [TcpForwarderHandler.forwarderDispatcher] kdoc. */
    private val ioDispatcher: CoroutineDispatcher = TcpForwarderHandler.forwarderDispatcher,
) {

    /**
     * Forward bytes between [conn] and [externalTarget]. Suspends
     * until both directions close. Closes both sides on return.
     */
    suspend fun forward(
        conn: WgTcpConnection,
        externalTarget: InetSocketAddress = conn.targetAddress,
    ) {
        val socket = withContext(ioDispatcher) {
            val s = socketFactory.createSocket()
            try {
                s.connect(externalTarget, connectTimeoutMs)
                s
            } catch (t: Throwable) {
                try { s.close() } catch (_: Exception) {}
                throw t
            }
        }
        coroutineScope {
            try {
                val outbound = launch(ioDispatcher) {
                    pump(conn.reader, socket.getOutputStream(),
                         closeWriterOnEof = ::halfCloseSocketOutput,
                         socket = socket)
                }
                val inbound = launch(ioDispatcher) {
                    pump(socket.getInputStream(), conn.writer,
                         closeWriterOnEof = ::closeWgWriter,
                         socket = null, wgConn = conn)
                }
                // join() suspends and is cancellation-aware. On
                // cancel it throws and we fall to the finally block.
                outbound.join()
                inbound.join()
            } finally {
                // Close the underlying streams to UNBLOCK any pump
                // that's stuck in a JNI-level read. Coroutine
                // cancellation alone doesn't interrupt
                // InputStream.read() — closing the source is what
                // makes the read return. After this, the pumps
                // throw IOException internally, hit their own
                // finally / catch, and complete. coroutineScope
                // then awaits them and returns (with the original
                // CancellationException, if cancelled).
                try { socket.close() } catch (_: Exception) {}
                try { conn.close() } catch (_: Exception) {}
            }
        }
    }

    /**
     * Copy bytes from [from] to [to] until EOF or error. On EOF,
     * call [closeWriterOnEof] so the *other* direction's read sees
     * EOF too (half-close propagation).
     */
    private fun pump(
        from: InputStream,
        to: OutputStream,
        closeWriterOnEof: (Socket?, WgTcpConnection?) -> Unit,
        socket: Socket?,
        wgConn: WgTcpConnection? = null,
    ) {
        val buf = ByteArray(bufferSize)
        try {
            while (true) {
                val n = from.read(buf)
                if (n < 0) break
                if (n == 0) continue
                to.write(buf, 0, n)
                to.flush()
            }
            // Source EOF — propagate half-close to the peer so they
            // know we're not going to send more bytes.
            try { closeWriterOnEof(socket, wgConn) } catch (_: Exception) {}
        } catch (_: IOException) {
            // Either side closed mid-pump; the finally block of the
            // forward() caller closes both ends. Don't re-throw —
            // the other direction may still have unread bytes.
        }
    }

    private fun halfCloseSocketOutput(socket: Socket?, conn: WgTcpConnection?) {
        try { socket?.shutdownOutput() } catch (_: Exception) {}
    }

    private fun closeWgWriter(socket: Socket?, conn: WgTcpConnection?) {
        // WgTcpConnection doesn't have a half-close primitive in its
        // contract — just close the writer side. The reader side
        // stays open until the peer closes from their end.
        try { conn?.writer?.close() } catch (_: Exception) {}
    }
}
