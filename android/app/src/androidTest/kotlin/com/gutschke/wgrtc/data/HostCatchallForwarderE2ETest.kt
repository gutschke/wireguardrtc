package com.gutschke.wgrtc.data

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
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
import java.net.ServerSocket
import java.security.SecureRandom
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * **end-to-end test for production full-tunnel routing.**
 *
 * Topology:
 *
 * joiner bridge (10.99.0.2) ←── WG ──→ host bridge (10.99.0.1)
 * │ │
 * │ joiner dials 10.99.0.1's │ catchall fwd installed
 * │ netstack at *any* port │ via WgBridgeBackend
 * │ │
 * │ ▼
 * │ target resolver remaps
 * │ 10.99.0.1:port → 127.0.0.1:port
 * │ │
 * │ ▼
 * │ real TCP / UDP server on loopback
 *
 * What this proves:
 *
 * 1. Installing the catchall via `installTcpCatchall` /
 * `installUdpCatchall` works on a real `RealWgBridgeBackendNative`.
 * 2. SYNs to a port the host doesn't have a per-port listener for
 * still reach the catchall + get forwarded to an OS socket.
 * 3. UDP datagrams round-trip via the per-flow OS socket the
 * `UdpForwarderHandler` opens.
 * 4. The host's outbound socket lands on a regular OS socket — the
 * same code path the production version uses to reach the
 * public internet. (We use loopback here for hermeticity.)
 *
 * **What's NOT tested here** but worth manual verification on real
 * hardware: cellular egress (emulator has no SIM), egress-policy
 * routing decisions (no real Wi-Fi vs. Cellular split on the
 * emulator), DNS proxy short-circuit (left for the production
 * smoke run since we'd need a fake DnsResolver).
 */
@RunWith(AndroidJUnit4::class)
class HostCatchallForwarderE2ETest {

    @Volatile private var hostHandle = 0
    @Volatile private var dialerHandle = 0
    @Volatile private var tcpCatchall: AutoCloseable? = null
    @Volatile private var udpCatchall: AutoCloseable? = null
    @Volatile private var dialerListenerId = 0
    @Volatile private var tcpServer: ServerSocket? = null
    @Volatile private var udpServer: DatagramSocket? = null
    @Volatile private var tcpThread: Thread? = null
    @Volatile private var udpThread: Thread? = null
    private val running = AtomicBoolean(true)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var hostBackend: RealWgBridgeBackendNative? = null

    @After fun tearDown() {
        running.set(false)
        try { tcpCatchall?.close() } catch (_: Throwable) {}
        try { udpCatchall?.close() } catch (_: Throwable) {}
        if (dialerListenerId > 0) {
            try { WgBridgeNative.nativeCloseListener(dialerListenerId) } catch (_: Throwable) {}
            UdpListenerRegistry.unregister(dialerListenerId)
        }
        try { tcpServer?.close() } catch (_: Throwable) {}
        try { udpServer?.close() } catch (_: Throwable) {}
        tcpThread?.interrupt()
        udpThread?.interrupt()
        if (dialerHandle > 0) WgBridgeNative.nativeClose(dialerHandle)
        hostBackend?.close()
        scope.cancel()
    }

    @Test fun tcpThroughCatchallRoundTrips() {
        // Real TCP echo server on the test JVM's loopback.
        val server = ServerSocket(0, 4, InetAddress.getByName("127.0.0.1"))
        tcpServer = server
        val echoPort = server.localPort
        tcpThread = Thread({
            while (running.get()) {
                val s = try { server.accept() } catch (_: Throwable) { break }
                Thread({
                    try {
                        val buf = ByteArray(1024)
                        val n = s.getInputStream().read(buf)
                        if (n > 0) s.getOutputStream().write(buf, 0, n)
                        s.getOutputStream().flush()
                    } catch (_: Throwable) {}
                    finally { try { s.close() } catch (_: Throwable) {} }
                }, "tcp-echo-conn").start()
            }
        }, "tcp-echo-server").apply { start() }

        bringUpTunnel()
        installCatchalls(echoPort, useTcp = true, useUdp = false)
        waitForHandshake(5_000)

        // Dial 10.99.0.1:echoPort through the tunnel. The catchall
        // on the host catches the SYN; target resolver remaps to
        // 127.0.0.1:echoPort (the test server).
        val connId = WgBridgeNative.nativeDialTcp(dialerHandle, "10.99.0.1:$echoPort")
        assertTrue("nativeDialTcp returned $connId", connId > 0)
        try {
            val payload = byteArrayOf(0x10, 0x20, 0x30, 0x40, 0x50)
            val wrote = WgBridgeNative.nativeTcpWrite(connId, payload, payload.size)
            assertEquals(payload.size, wrote)
            val recv = ByteArray(payload.size)
            val read = WgBridgeNative.nativeTcpRead(connId, recv, recv.size)
            assertEquals("echo length mismatch", payload.size, read)
            assertArrayEquals("echo bytes differ", payload, recv)
        } finally {
            try { WgBridgeNative.nativeTcpClose(connId) } catch (_: Throwable) {}
        }
    }

    @Test fun udpThroughCatchallRoundTrips() {
        // Real UDP echo server on loopback.
        val server = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        udpServer = server
        val echoPort = server.localPort
        udpThread = Thread({
            val buf = ByteArray(2048)
            while (running.get()) {
                val pkt = DatagramPacket(buf, buf.size)
                try { server.receive(pkt) } catch (_: Throwable) { break }
                val reply = DatagramPacket(pkt.data, pkt.length, pkt.address, pkt.port)
                try { server.send(reply) } catch (_: Throwable) { break }
            }
        }, "udp-echo-server").apply { start() }

        bringUpTunnel()
        installCatchalls(echoPort, useTcp = false, useUdp = true)
        waitForHandshake(5_000)

        // Joiner-side listener so we can receive the echo reply.
        val rxQueue = LinkedBlockingQueue<ByteArray>()
        dialerListenerId = WgBridgeNative.nativeListenUdp(dialerHandle, 0)
        assertTrue("nativeListenUdp=$dialerListenerId", dialerListenerId > 0)
        val joinerSink = WgUdpSinkNative(dialerListenerId)
        UdpListenerRegistry.register(dialerListenerId, object : WgUdpReceiver {
            override fun onDatagram(peerAddr: String, listenAddr: String, data: ByteArray) {
                rxQueue.put(data)
            }
        }, joinerSink)

        // Dial 10.99.0.1:echoPort over UDP. Same catchall semantics
        // as TCP — host's UdpForwarderHandler opens a per-flow OS
        // socket to 127.0.0.1:echoPort, pumps bytes both ways.
        val payload = ByteArray(48).also { SecureRandom().nextBytes(it) }
        joinerSink.sendTo("10.99.0.1:$echoPort", payload)
        val reply = rxQueue.poll(5, TimeUnit.SECONDS)
        assertTrue("no echoed datagram within 5s", reply != null)
        assertArrayEquals("UDP echo mismatch", payload, reply)
    }

    // ── Test fixture helpers ──────────────────────────────────────

    private fun bringUpTunnel() {
        val (hostPriv, hostPub) = newKeyPair()
        val (dialerPriv, dialerPub) = newKeyPair()
        val wgPort = 52000 + SecureRandom().nextInt(500)

        // Build the host through RealWgBridgeBackendNative so we
        // exercise the install methods we The
        // joiner stays on the raw JNI calls — it's just a peer.
        hostBackend = RealWgBridgeBackendNative.open("10.99.0.1",
            MtuMath.DEFAULT_WG_MTU, wgPort)
        // For test convenience, also pin the handle int so we can
        // call nativeSnapshotUAPI directly for the handshake wait.
        hostHandle = readHandle(hostBackend!!)
        hostBackend!!.configureUapi(buildString {
            append("private_key=").append(hostPriv).append('\n')
            append("listen_port=").append(wgPort).append('\n')
            append("replace_peers=true\n")
            append("public_key=").append(dialerPub).append('\n')
            append("allowed_ip=10.99.0.2/32\n")
        })

        dialerHandle = WgBridgeNative.nativeNew("10.99.0.2",
            MtuMath.DEFAULT_WG_MTU, 0)
        assertTrue("dialer nativeNew=$dialerHandle", dialerHandle > 0)
        assertEquals(0, WgBridgeNative.nativeConfigureUAPI(dialerHandle,
            buildString {
                append("private_key=").append(dialerPriv).append('\n')
                append("listen_port=0\n")
                append("replace_peers=true\n")
                append("public_key=").append(hostPub).append('\n')
                append("endpoint=127.0.0.1:").append(wgPort).append('\n')
                append("allowed_ip=10.99.0.1/32\n")
                append("persistent_keepalive_interval=1\n")
            }))
    }

    private fun installCatchalls(echoPort: Int, useTcp: Boolean, useUdp: Boolean) {
        // Identity-with-loopback-remap resolver: anything the joiner
        // aimed at gets rewritten to 127.0.0.1:port (the test server)
        // so we don't depend on real internet from the emulator.
        val remap: (String, String) -> InetSocketAddress? = { _, origDest ->
            val colon = origDest.lastIndexOf(':')
            val port = origDest.substring(colon + 1).toInt()
            InetSocketAddress("127.0.0.1", port)
        }
        if (useTcp) {
            val handler = TcpForwarderHandler(targetResolver = remap)
            tcpCatchall = hostBackend!!.installTcpCatchall(handler, scope)
        }
        if (useUdp) {
            val handler = UdpForwarderHandler(targetResolver = remap)
            udpCatchall = hostBackend!!.installUdpCatchall(handler, scope)
        }
    }

    /** Reflection back-door so we can call `nativeSnapshotUAPI` on
     * the host's raw int handle. In production this would be
     * through the WgBridgeBackend.snapshotUapi() abstraction, but
     * the test wants the raw handle for parity with the other
     * Nat*E2ETests. */
    private fun readHandle(backend: RealWgBridgeBackendNative): Int {
        val f = RealWgBridgeBackendNative::class.java
            .getDeclaredField("handle").apply { isAccessible = true }
        return f.getInt(backend)
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
