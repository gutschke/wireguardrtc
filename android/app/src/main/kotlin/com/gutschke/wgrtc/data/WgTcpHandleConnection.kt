package com.gutschke.wgrtc.data

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress

/**
 * Adapt a [WgTcpHandle] (raw byte-array read/write surface from
 * `wgbridge.TCPConnHandle`) to a [WgTcpConnection] (InputStream /
 * OutputStream). The existing [TcpFlowForwarder] consumes
 * [WgTcpConnection], so this is the bridge point between the
 * gomobile API and the forwarder.
 *
 * Address parsing: gomobile gives us a string like "10.99.0.2:54321".
 * We split on the LAST `:` so that IPv6 addresses (if we ever support
 * them) wouldn't trip up on the embedded colons of an
 * `[fd00::1]:port` form — but keep in mind WG hole-punching is IPv4
 * only; this is just defensive parsing.
 */
class WgTcpHandleConnection(
    private val handle: WgTcpHandle,
    /**
     * Caller-supplied destination the peer was trying to reach. The
     * netstack TCP listener doesn't expose the inner-IP destination
     * separately from the listen address (we bound on `0.0.0.0:port`,
     * so [WgTcpHandle.listenAddress] is the listen socket name, not
     * the dst the peer actually sent to). The caller resolves this
     * out-of-band — typically from the `target =` field of the
     * tunnel's HostModeConfig.
     */
    override val targetAddress: InetSocketAddress,
) : WgTcpConnection {

    override val peerAddress: InetSocketAddress = parseHostPort(handle.peerAddress)

    override val reader: InputStream = HandleInputStream(handle)
    override val writer: OutputStream = HandleOutputStream(handle)

    override fun close() {
        // Closing the handle unblocks any in-flight read/write on
        // the streams above (gomobile maps it to closing the
        // underlying netstack TCPConn).
        handle.close()
    }
}

/**
 * Bridges [WgTcpHandle.read] (returns -1 at EOF) to [InputStream]'s
 * `read(byte[], int, int) -> int`.
 *
 * Performance note: if `off != 0` or `len != buf.size`, we allocate
 * a temporary buffer because the Go-side API takes the whole array.
 * Most callers (including [TcpFlowForwarder.pump]) read into a fresh
 * `ByteArray(bufferSize)` from offset 0, so the slow path stays
 * cold.
 */
private class HandleInputStream(private val handle: WgTcpHandle) : InputStream() {
    override fun read(): Int {
        val one = ByteArray(1)
        val n = read(one, 0, 1)
        return if (n < 0) -1 else (one[0].toInt() and 0xff)
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (len == 0) return 0
        if (off < 0 || len < 0 || off + len > b.size) {
            throw IndexOutOfBoundsException("off=$off len=$len size=${b.size}")
        }
        val n = if (off == 0 && len == b.size) {
            handle.read(b)
        } else {
            val tmp = ByteArray(len)
            val rc = handle.read(tmp)
            if (rc > 0) System.arraycopy(tmp, 0, b, off, rc)
            rc
        }
        return n // -1 at EOF passes through; >0 is a real read.
    }

    override fun close() {
        // No-op: the WgTcpHandleConnection owns the handle's
        // lifetime; closing the InputStream alone wouldn't make
        // sense (there'd be no way to write the response). The
        // forwarder's finally clause closes the connection itself.
    }
}

/**
 * Bridges [WgTcpHandle.write] (slice-only) to [OutputStream]'s
 * `write(byte[], int, int)`.
 */
private class HandleOutputStream(private val handle: WgTcpHandle) : OutputStream() {
    override fun write(b: Int) {
        handle.write(byteArrayOf(b.toByte()))
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (off < 0 || len < 0 || off + len > b.size) {
            throw IndexOutOfBoundsException("off=$off len=$len size=${b.size}")
        }
        if (off == 0 && len == b.size) {
            handle.write(b)
        } else {
            val tmp = ByteArray(len)
            System.arraycopy(b, off, tmp, 0, len)
            handle.write(tmp)
        }
    }

    override fun close() {
        // See HandleInputStream.close — the handle's lifetime is
        // owned by the connection. shutdownOutput-style half-close
        // isn't supported by netstack's gonet.TCPConn through
        // gomobile, so we'd have nothing to do here either way.
    }
}

