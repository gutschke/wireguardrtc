package com.gutschke.wgrtc.data

import android.util.Log
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.net.SocketFactory

/**
 * TCP catchall forwarder. Receives a forwarded TCP accept from the
 * netstack (joiner dialed some address inside the tunnel), opens an
 * outbound socket through [socketFactory] to either the original
 * dst or whatever [targetResolver] redirects to, and hands both
 * halves to [TcpFlowForwarder] for bidirectional pumping.
 *
 * Each accept runs on its own coroutine so slow dials don't block
 * the accept loop. Every open path closes both sockets on error.
 */
class TcpForwarderHandler(
    /** Where outbound sockets come from. Default uses the OS
     * primary network; 's egress selector swaps this for a
     * Network-bound factory. */
    private val socketFactory: SocketFactory = SocketFactory.getDefault(),
    /** Per-accept policy: given (peer, origDest), decide where
     * the outbound socket should connect (or null to refuse).
     * Production wiring: identity — return the parsed
     * origDest unchanged. Tests override to deny / redirect. */
    private val targetResolver: (peer: String, origDest: String) -> InetSocketAddress?,
    /** Hook fired when a forward has been established (after
     * the outbound socket connected successfully). Default
     * no-op; used by tests + metrics. */
    private val onForwardStart: (peer: String, target: InetSocketAddress) -> Unit = { _, _ -> },
    /** Hook fired when a forward ends (either side closed
     * cleanly OR errored). */
    private val onForwardEnd: (peer: String, target: InetSocketAddress) -> Unit = { _, _ -> },
    /** TcpFlowForwarder instance; injectable for tests. */
    private val flowForwarder: TcpFlowForwarder = TcpFlowForwarder(),
    /** Dispatcher for the blocking outbound connect + byte pumps.
     * Defaults to [forwarderDispatcher] (an unbounded cached
     * thread pool, see kdoc on that field) so per-flow thread
     * pinning can't exhaust the shared `Dispatchers.IO` budget.
     * Tests override to keep all coroutines on the test scheduler
     * so `advanceUntilIdle()` is reliable. */
    private val ioDispatcher: CoroutineDispatcher = forwarderDispatcher,
    private val tag: String = "wgrtc-fwd-tcp",
) {

    /**
     * Dispatch an accepted forwarded TCP connection. Returns
     * immediately; the actual byte pump runs in a coroutine on
     * [scope].
     */
    fun dispatch(
        scope: CoroutineScope,
        peerAddr: String,
        origDest: String,
        wg: WgTcpHandle,
    ) {
        scope.launch {
            handleOne(peerAddr, origDest, wg)
        }
    }

    private suspend fun handleOne(peerAddr: String, origDest: String, wg: WgTcpHandle) {
        val parsed = parseHostPort(origDest)
        if (parsed == null) {
            Log.w(tag, "unparseable origDest=$origDest from $peerAddr; closing")
            wg.close()
            return
        }
        val target = targetResolver(peerAddr, origDest)
        if (target == null) {
            Log.i(tag, "resolver refused $peerAddr → $origDest")
            wg.close()
            return
        }
        Log.i(tag, "accept $peerAddr → $origDest; dialing $target")
        // `createSocket(host, port)` on the JDK default factory
        // connects synchronously with no timeout; use the unconnected
        // form + explicit `connect(target, CONNECT_TIMEOUT_MS)` so we
        // honor our own deadline regardless of factory choice.
        val socket: Socket = try {
            withContext(ioDispatcher) {
                val s = socketFactory.createSocket()
                if (!s.isConnected) s.connect(target, CONNECT_TIMEOUT_MS)
                s
            }
        } catch (e: Throwable) {
            Log.w(tag, "outbound connect to $target failed for $peerAddr: ${e.javaClass.simpleName}: ${e.message}")
            wg.close()
            return
        }
        Log.i(tag, "connected $peerAddr → $target; pumping bytes")
        val openCount = openFlows.incrementAndGet()
        val startNs = System.nanoTime()
        // Hand off to the flow forwarder. It owns both sides
        // for the duration of the flow + cleans up at end.
        onForwardStart(peerAddr, target)
        try {
            val peerSocket = parseHostPort(peerAddr) ?: InetSocketAddress(0)
            val wgConn = WgTcpConnectionAdapter(
                handle = wg,
                peerAddress = peerSocket,
                targetAddress = target,
            )
            flowForwarder.forward(wgConn, target)
            Log.i(tag, "ended $peerAddr → $target after ${(System.nanoTime() - startNs) / 1_000_000} ms (open=${openCount - 1})")
        } catch (e: Throwable) {
            Log.w(tag, "forward $peerAddr → $target ended with error after ${(System.nanoTime() - startNs) / 1_000_000} ms: ${e.message}")
        } finally {
            openFlows.decrementAndGet()
            // Belt-and-suspenders close — TcpFlowForwarder
            // closes both sides on its own, but if it threw
            // before reaching that point we still need to
            // tidy up.
            try { socket.close() } catch (_: Throwable) {}
            try { wg.close() } catch (_: Throwable) {}
            onForwardEnd(peerAddr, target)
        }
    }

    private fun parseHostPort(s: String): InetSocketAddress? {
        // Accept either "host:port" or "[v6addr]:port" (gvisor's
        // String() formatter emits unbracketed for v4 + bracketed
        // for v6).
        val colon = s.lastIndexOf(':')
        if (colon <= 0 || colon == s.length - 1) return null
        val host = s.substring(0, colon).trim().trim('[', ']')
        val port = s.substring(colon + 1).trim().toIntOrNull() ?: return null
        if (port !in 1..65535) return null
        return try { InetSocketAddress(host, port) } catch (_: Throwable) { null }
    }

    /** Gauge of how many TCP flows are currently being pumped.
     * Surfaced into every per-flow end-of-life log so a saturated
     * forwarder is visible at a glance. */
    private val openFlows = AtomicInteger(0)

    companion object {
        /** Connect timeout in ms. Wide enough for cellular RTT
         * but short enough that a wrong dst doesn't hang the
         * flow indefinitely. */
        const val CONNECT_TIMEOUT_MS = 10_000

        /**
         * Shared dispatcher backing the host-mode forwarder's
         * blocking I/O (connect, byte pumps).
         *
         * **Why not `Dispatchers.IO`.** The host forwarder pumps
         * pin one thread per direction per flow (`InputStream.read`
         * blocks until bytes arrive). A user with ~30 long-lived
         * keepalive connections (Chrome HTTPS, FCM, Cast,
         * Messenger, etc.) pins ~60 threads — at or above the
         * default `Dispatchers.IO` parallelism of 64. Once that
         * pool saturates, new TCP `connect` calls queue forever
         * and the user sees the symptom "TCP works for a while
         * then hangs" (real-device log from 2026-05-11 has 18
         * accepts but only 10 reaching `connected`).
         *
         * Solution: dedicated cached thread pool that grows on
         * demand and reaps idle threads after 60 s. Daemon
         * threads so they don't pin the JVM at process exit.
         */
        val forwarderDispatcher: CoroutineDispatcher = run {
            val n = AtomicInteger()
            Executors.newCachedThreadPool { r ->
                Thread(r, "wgrtc-fwd-io-${n.incrementAndGet()}").apply {
                    isDaemon = true
                }
            }.also {
                // Same idle reap timeout as the default cached
                // pool (60 s) — explicit for clarity.
                (it as java.util.concurrent.ThreadPoolExecutor)
                    .setKeepAliveTime(60, TimeUnit.SECONDS)
            }.asCoroutineDispatcher()
        }
    }
}

/**
 * Adapter from a [WgTcpHandle] (our JNI surface; address as
 * "host:port" string) to a [WgTcpConnection] (the API
 * [TcpFlowForwarder] consumes; addresses typed
 * [InetSocketAddress]).
 */
private class WgTcpConnectionAdapter(
    private val handle: WgTcpHandle,
    override val peerAddress: InetSocketAddress,
    override val targetAddress: InetSocketAddress,
) : WgTcpConnection {

    override val reader: java.io.InputStream = object : java.io.InputStream() {
        private val one = ByteArray(1)
        override fun read(): Int {
            val n = handle.read(one)
            return if (n <= 0) -1 else one[0].toInt() and 0xff
        }
        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            // WgTcpHandle.read fills from offset 0; copy in if
            // offset != 0.
            return if (off == 0) {
                val n = handle.read(b)
                if (n <= 0) -1 else n
            } else {
                val tmp = ByteArray(len)
                val n = handle.read(tmp)
                if (n <= 0) -1 else {
                    System.arraycopy(tmp, 0, b, off, n)
                    n
                }
            }
        }
        override fun close() = handle.close()
    }

    override val writer: java.io.OutputStream = object : java.io.OutputStream() {
        private val one = ByteArray(1)
        override fun write(b: Int) {
            one[0] = b.toByte()
            handle.write(one)
        }
        override fun write(b: ByteArray, off: Int, len: Int) {
            val slice = if (off == 0 && len == b.size) b else b.copyOfRange(off, off + len)
            handle.write(slice)
        }
        override fun close() = handle.close()
    }

    override fun close() = handle.close()
}
