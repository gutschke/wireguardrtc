package com.gutschke.wgrtc.data

import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress

/**
 * One TCP connection accepted via the userspace WG endpoint
 * (see `docs/PHASE5_USERSPACE_WG_FEASIBILITY.md`).
 *
 * After wgbridge's netstack TCP listener accepts a connection from
 * a hotspot peer, we wrap the netstack `gonet.TCPConn` (Java-side
 * via gomobile) in this interface. The forwarder pumps bytes
 * between this connection and a regular [java.net.Socket] outbound
 * to the destination.
 *
 * peer ─WG─→ wgbridge listener ─→ WgTcpConnection ─→ TcpFlowForwarder ─→ Socket(dst)
 * ↑
 * routes via the
 * active VpnService
 * (or default route)
 *
 * Implementations:
 * - production: a wrapper around the Go-side `Conn` handle
 * (wgbridge integration; not yet built).
 * - tests: [TcpFlowForwarderTest.FakeWgTcpConnection] uses a
 * [java.io.PipedInputStream] / [java.io.PipedOutputStream] pair.
 *
 * Closing the connection MUST shut down both [reader] and [writer]
 * even if one direction has already EOF'd — the forwarder relies on
 * close-propagation to terminate cleanly.
 */
interface WgTcpConnection {
    /** Bytes from the WG peer (after WG-decrypt + netstack TCP). */
    val reader: InputStream

    /** Bytes to the WG peer (will be WG-encrypted on the way out). */
    val writer: OutputStream

    /** The peer's WG-side source address (assigned by the host's
     * HostModeConfig subnet, e.g. `10.99.0.2:54321`). */
    val peerAddress: InetSocketAddress

    /** The destination address the peer is trying to reach
     * (extracted from the inner IP packet, before our forwarder
     * decided where to actually open a Socket). */
    val targetAddress: InetSocketAddress

    fun close()
}
