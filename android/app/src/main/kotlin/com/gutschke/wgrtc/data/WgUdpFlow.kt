package com.gutschke.wgrtc.data

import java.net.InetSocketAddress

/**
 * One UDP flow accepted via the userspace WG endpoint
 * (). Each unique (peer-source, peer-target) tuple
 * the wgbridge listener sees becomes one [WgUdpFlow], delivered to
 * the forwarder.
 *
 * Datagrams arrive via [receive] (suspends until the next datagram
 * or the flow is closed). Replies go out via [send] (will be
 * WG-encrypted on egress to the peer). [close] tears down the
 * flow; subsequent [receive] returns null.
 *
 * Implementations:
 * - production: a wrapper around the netstack `gonet.UDPConn`
 * (wgbridge integration).
 * - tests: [UdpFlowForwarderTest.FakeWgUdpFlow] uses kotlinx
 * Channels to simulate the peer side.
 */
interface WgUdpFlow {
    val peerAddress: InetSocketAddress
    val targetAddress: InetSocketAddress

    /** Wait for the next datagram from the WG peer. Returns null
     * when the flow is closed (cleanly or due to error). */
    suspend fun receive(): ByteArray?

    /** Send a datagram back to the WG peer. Idempotent on errors —
     * delivery isn't guaranteed (it's UDP). */
    suspend fun send(data: ByteArray)

    /** Tear down the flow. Subsequent [receive] returns null. */
    fun close()
}
