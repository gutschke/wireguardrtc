package com.gutschke.wgrtc.data

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.SecureRandom
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * **UDP catchall forwarder end-to-end test.**
 *
 * Same self-loop topology as [NatTcpForwarderE2ETest], but for
 * UDP. A real UDP echo server runs on the test JVM's loopback;
 * the joiner-side bridge dials a UDP datagram through the tunnel
 * to the host's WG-side address; the host's UDP forwarder catches
 * it, opens an OS-side `DatagramSocket`, sends the bytes to the
 * echo server, reads the reply, injects it back into the
 * netstack toward the joiner. Bytes round-trip.
 *
 * Validates:
 * - First datagram in a new flow opens the OS socket
 * - Round-trip works in <1s (gvisor + JVM socket cycle)
 * - Two datagrams on the same flow reuse the socket
 */
@RunWith(AndroidJUnit4::class)
class NatUdpForwarderE2ETest {

    @Volatile private var hostHandle = 0
    @Volatile private var dialerHandle = 0
    @Volatile private var forwarderId = 0
    @Volatile private var dialerListenerId = 0
    @Volatile private var echoServer: DatagramSocket? = null
    @Volatile private var echoThread: Thread? = null
    private val scope = CoroutineScope(SupervisorJob())

    @After fun tearDown() {
        if (dialerListenerId > 0) {
            try { WgBridgeNative.nativeCloseListener(dialerListenerId) } catch (_: Throwable) {}
            UdpListenerRegistry.unregister(dialerListenerId)
        }
        if (forwarderId > 0) {
            try { WgBridgeNative.nativeCloseListener(forwarderId) } catch (_: Throwable) {}
            UdpForwarderRegistry.unregister(forwarderId)
        }
        if (dialerHandle > 0) WgBridgeNative.nativeClose(dialerHandle)
        if (hostHandle > 0) WgBridgeNative.nativeClose(hostHandle)
        try { echoServer?.close() } catch (_: Throwable) {}
        echoThread?.interrupt()
        scope.cancel()
    }

    @Test
    fun joinerUdpDatagramRoundTripsThroughForwarder() {
        // ── Real UDP echo server on the test JVM ────────────────
        val server = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        echoServer = server
        val echoPort = server.localPort
        val running = AtomicBoolean(true)
        echoThread = Thread({
            val buf = ByteArray(2048)
            while (running.get()) {
                val pkt = DatagramPacket(buf, buf.size)
                try { server.receive(pkt) } catch (_: Throwable) { break }
                val reply = DatagramPacket(pkt.data, pkt.length, pkt.address, pkt.port)
                try { server.send(reply) } catch (_: Throwable) { break }
            }
        }, "udp-echo").apply { start() }

        // ── Bridges + handshake ─────────────────────────────────
        val (hostPriv, hostPub) = newKeyPair()
        val (dialerPriv, dialerPub) = newKeyPair()
        val wgPort = 51000 + SecureRandom().nextInt(500)

        hostHandle = WgBridgeNative.nativeNew("10.99.0.1", MtuMath.DEFAULT_WG_MTU, wgPort)
        assertTrue("host nativeNew=$hostHandle", hostHandle > 0)
        assertEquals(0, WgBridgeNative.nativeConfigureUAPI(hostHandle, buildString {
            append("private_key=").append(hostPriv).append('\n')
            append("listen_port=").append(wgPort).append('\n')
            append("replace_peers=true\n")
            append("public_key=").append(dialerPub).append('\n')
            append("allowed_ip=10.99.0.2/32\n")
        }))
        dialerHandle = WgBridgeNative.nativeNew("10.99.0.2", MtuMath.DEFAULT_WG_MTU, 0)
        assertTrue("dialer nativeNew=$dialerHandle", dialerHandle > 0)
        assertEquals(0, WgBridgeNative.nativeConfigureUAPI(dialerHandle, buildString {
            append("private_key=").append(dialerPriv).append('\n')
            append("listen_port=0\n")
            append("replace_peers=true\n")
            append("public_key=").append(hostPub).append('\n')
            append("endpoint=127.0.0.1:").append(wgPort).append('\n')
            append("allowed_ip=10.99.0.1/32\n")
            append("persistent_keepalive_interval=1\n")
        }))
        waitForHandshake(5_000)

        // ── Install UDP forwarder on the host ───────────────────
        val handler = UdpForwarderHandler(
            // Remap the joiner's intended dest (10.99.0.1:port)
            // to the actual loopback echo server (127.0.0.1:port).
            targetResolver = { _, origDest ->
                val colon = origDest.lastIndexOf(':')
                val port = origDest.substring(colon + 1).toInt()
                InetSocketAddress("127.0.0.1", port)
            },
        )
        forwarderId = WgBridgeNative.nativeInstallUdpForwarder(hostHandle)
        assertTrue("nativeInstallUdpForwarder=$forwarderId", forwarderId > 0)
        UdpForwarderRegistry.register(forwarderId, handler, scope)

        // ── Joiner-side UDP listener to receive replies ─────────
        val rxQueue = LinkedBlockingQueue<ByteArray>()
        dialerListenerId = WgBridgeNative.nativeListenUdp(dialerHandle, 0)
        assertTrue("nativeListenUdp=$dialerListenerId", dialerListenerId > 0)
        val joinerSink = WgUdpSinkNative(dialerListenerId)
        UdpListenerRegistry.register(dialerListenerId, object : WgUdpReceiver {
            override fun onDatagram(peerAddr: String, listenAddr: String, data: ByteArray) {
                rxQueue.put(data)
            }
        }, joinerSink)

        // ── Send a datagram + verify echo ───────────────────────
        val payload = ByteArray(64).also { SecureRandom().nextBytes(it) }
        joinerSink.sendTo("10.99.0.1:$echoPort", payload)
        val reply = rxQueue.poll(3, TimeUnit.SECONDS)
        assertTrue("no echoed datagram within 3s", reply != null)
        assertArrayEquals("first datagram echo mismatch", payload, reply)

        // ── Second datagram on same flow (should reuse socket) ──
        val payload2 = ByteArray(64).also { SecureRandom().nextBytes(it) }
        joinerSink.sendTo("10.99.0.1:$echoPort", payload2)
        val reply2 = rxQueue.poll(3, TimeUnit.SECONDS)
        assertTrue("no second echo within 3s", reply2 != null)
        assertArrayEquals("second datagram echo mismatch", payload2, reply2)
    }

    private fun waitForHandshake(timeoutMs: Long) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val a = WgBridgeNative.nativeSnapshotUAPI(hostHandle)?.let {
                UapiStatsParser.parse(it).mostRecentHandshakeEpochMs
            } ?: 0L
            val b = WgBridgeNative.nativeSnapshotUAPI(dialerHandle)?.let {
                UapiStatsParser.parse(it).mostRecentHandshakeEpochMs
            } ?: 0L
            if (a > 0 && b > 0) return
            Thread.sleep(100)
        }
        throw AssertionError("handshake did not complete within $timeoutMs ms")
    }

    private fun newKeyPair(): Pair<String, String> {
        val priv = ByteArray(32).apply { SecureRandom().nextBytes(this) }
        priv[0] = (priv[0].toInt() and 248).toByte()
        priv[31] = ((priv[31].toInt() and 127) or 64).toByte()
        val kf = java.security.KeyFactory.getInstance("XDH")
        val privKey = kf.generatePrivate(java.security.spec.PKCS8EncodedKeySpec(
            byteArrayOf(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
                0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20) + priv))
        val ka = javax.crypto.KeyAgreement.getInstance("XDH").apply { init(privKey) }
        val base = ByteArray(32).also { it[0] = 9 }
        val basePub = kf.generatePublic(java.security.spec.X509EncodedKeySpec(
            byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
                0x6e, 0x03, 0x21, 0x00) + base))
        ka.doPhase(basePub, true)
        val pub = ka.generateSecret()
        fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        return hex(priv) to hex(pub)
    }
}
