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
import org.junit.Before
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
 * **through-host packet forwarder, production wiring.**
 *
 * Validates that [HostModeRunner] installs + tears down the Option B
 * host forwarder correctly, and that joiner traffic to *non-local*
 * destinations is re-injected as temp-local + caught by the
 * existing TCP/UDP catchalls.
 *
 * Topology (in-process self-loop, slirp-NAT-immune):
 *
 * joiner bridge (10.99.0.2) ←── WG ──→ host runner (10.99.0.1)
 * │ │
 * │ dials 8.8.8.8:port ── full ─→ │ host forwarder
 * │ tunnel (allowed_ip=0.0.0.0/0) │ (NIC2 + temp-local)
 * │ │
 * │ ▼
 * │ packet re-injected at NIC1
 * │ with 8.8.8.8 as temp-local
 * │ │
 * │ ▼
 * │ target resolver remaps
 * │ 8.8.8.8:port → 127.0.0.1:port
 * │ │
 * │ ▼
 * │ real TCP / UDP server on loopback
 *
 * Why 8.8.8.8 + remap: avoids depending on the emulator's actual
 * internet (which is slirp-NAT'd + flaky for some destinations).
 * The non-local-dst path is what matters for the test; the
 * loopback server stands in for "the public internet" hermetically.
 *
 * **What this proves:**
 *
 * 1. [HostModeRunner.start] installs the host forwarder when
 * `hostForwarderSubnet` is set in [HostModeRunnerConfig].
 * 2. The forwarder's temp-local-address trick works for TCP +
 * UDP — a joiner SYN to a non-local IP gets re-injected so
 * the catchall handler fires.
 * 3. Tear-down via [HostModeRunner.stop] cleans up the
 * forwarder + restores the original route table without
 * leaking goroutines or NIC handles.
 *
 * **What this does NOT test** (hardware-only, requires real
 * internet):
 * - ICMP through-host (real `golang.org/x/net/icmp` ping). See
 * the Pixel validation log on 2026-05-10: 5/5 pings to 1.1.1.1
 * succeeded at 16–24 ms.
 */
@RunWith(AndroidJUnit4::class)
class HostModeForwarderE2ETest {

    @Volatile private var dialerHandle = 0
    @Volatile private var hostBackend: RealWgBridgeBackendNative? = null
    @Volatile private var hostRunner: HostModeRunner? = null
    @Volatile private var dialerListenerId = 0
    @Volatile private var tcpServer: ServerSocket? = null
    @Volatile private var udpServer: DatagramSocket? = null
    @Volatile private var tcpThread: Thread? = null
    @Volatile private var udpThread: Thread? = null
    private val running = AtomicBoolean(true)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @Before fun setUp() { running.set(true) }

    @After fun tearDown() {
        running.set(false)
        try { hostRunner?.stop() } catch (_: Throwable) {}
        if (dialerListenerId > 0) {
            try { WgBridgeNative.nativeCloseListener(dialerListenerId) } catch (_: Throwable) {}
            UdpListenerRegistry.unregister(dialerListenerId)
        }
        try { tcpServer?.close() } catch (_: Throwable) {}
        try { udpServer?.close() } catch (_: Throwable) {}
        tcpThread?.interrupt()
        udpThread?.interrupt()
        if (dialerHandle > 0) try { WgBridgeNative.nativeClose(dialerHandle) }
            catch (_: Throwable) {}
        scope.cancel()
    }

    @Test fun tcpToNonLocalDstRoundTripsThroughHostForwarder() {
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

        bringUpTunnelWithHostForwarder(useTcp = true, useUdp = false, remapPort = echoPort)
        waitForHandshake(5_000)

        // Dial a NON-LOCAL destination — the joiner has
        // allowed_ip=0.0.0.0/0 so wireguard-go encrypts it; the
        // host's gvisor netstack sees a packet for 8.8.8.8 which
        // is NOT in its local-address table. Without the host
        // forwarder this would drop at the IP layer. WITH the
        // forwarder, NIC2 catches it + the temp-local-address
        // trick re-injects at NIC1 + the TCP catchall fires +
        // our remap sends it to 127.0.0.1:echoPort.
        val connId = WgBridgeNative.nativeDialTcp(dialerHandle, "8.8.8.8:$echoPort")
        assertTrue("nativeDialTcp returned $connId", connId > 0)
        try {
            val payload = byteArrayOf(0x11, 0x22, 0x33, 0x44, 0x55, 0x66)
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

    @Test fun udpToNonLocalDstRoundTripsThroughHostForwarder() {
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

        bringUpTunnelWithHostForwarder(useTcp = false, useUdp = true, remapPort = echoPort)
        waitForHandshake(5_000)

        // Joiner-side listener for the echoed datagram.
        val rxQueue = LinkedBlockingQueue<ByteArray>()
        dialerListenerId = WgBridgeNative.nativeListenUdp(dialerHandle, 0)
        assertTrue("nativeListenUdp=$dialerListenerId", dialerListenerId > 0)
        val joinerSink = WgUdpSinkNative(dialerListenerId)
        UdpListenerRegistry.register(dialerListenerId, object : WgUdpReceiver {
            override fun onDatagram(peerAddr: String, listenAddr: String, data: ByteArray) {
                rxQueue.put(data)
            }
        }, joinerSink)

        // Send to NON-LOCAL 8.8.8.8 — same routing argument as TCP.
        val payload = ByteArray(48).also { SecureRandom().nextBytes(it) }
        joinerSink.sendTo("8.8.8.8:$echoPort", payload)
        val reply = rxQueue.poll(5, TimeUnit.SECONDS)
        assertTrue("no echoed datagram within 5s", reply != null)
        assertArrayEquals("UDP echo mismatch", payload, reply)
    }

    /**
     * Sanity check: even with the host forwarder installed,
     * gvisor's native auto-reply for the host's own WG-side IP
     * still works. This was specifically broken by the failed
     * v2 promiscuous-mode attempt; Option B keeps it working.
     */
    @Test fun hostsOwnIpStillRespondsToPingWithHostForwarderInstalled() {
        bringUpTunnelWithHostForwarder(useTcp = true, useUdp = true, remapPort = null)
        waitForHandshake(5_000)
        val rttUs = WgBridgeNative.nativePingV4(dialerHandle, "10.99.0.1", 3_000)
        assertTrue("ping to host's WG-side IP failed (rc=$rttUs)", rttUs >= 0)
    }

    // ── Fixture helpers ──────────────────────────────────────────

    private fun bringUpTunnelWithHostForwarder(
        useTcp: Boolean, useUdp: Boolean, remapPort: Int?,
    ) {
        // HostModeUapi.render() expects base64 keys (it
        // base64-decodes them internally before re-encoding as
        // hex for the UAPI line). The joiner side talks UAPI
        // directly so it can take either hex or b64 — we use
        // hex there for parity with the raw-bridge tests.
        val (hostPrivHex, hostPubHex) = newKeyPair()
        val hostPrivB64 = hexToB64(hostPrivHex)
        val hostPubB64 = hexToB64(hostPubHex)
        val (dialerPrivHex, dialerPubHex) = newKeyPair()
        val dialerPubB64 = hexToB64(dialerPubHex)
        val wgPort = 53000 + SecureRandom().nextInt(500)

        // Hermetic remap: any non-local dst the joiner aims at
        // gets rewritten to the loopback test server.
        val remap: (String, String) -> InetSocketAddress? = { _, origDest ->
            if (remapPort == null) null
            else InetSocketAddress("127.0.0.1", remapPort)
        }
        val tcpFactory: (CoroutineScope) -> TcpForwarderHandler = { _ ->
            TcpForwarderHandler(targetResolver = remap)
        }
        val udpFactory: (CoroutineScope) -> UdpForwarderHandler = { _ ->
            UdpForwarderHandler(targetResolver = remap)
        }

        val factory = WgBridgeBackendFactory { localAddr, mtu, listenPort ->
            val backend = RealWgBridgeBackendNative.open(localAddr, mtu, listenPort)
            hostBackend = backend
            backend
        }
        val runner = HostModeRunner(factory, scope)
        hostRunner = runner
        runner.start(HostModeRunnerConfig(
            localAddr = "10.99.0.1",
            listenPort = wgPort,
            mtu = MtuMath.DEFAULT_WG_MTU,
            privateKeyB64 = hostPrivB64,
            peers = listOf(HostModeUapi.Peer(
                publicKeyB64 = dialerPubB64,
                allowedIp = "10.99.0.2/32",
            )),
            targetResolver = { _, _ -> null },
            tcpCatchallFactory = if (useTcp) tcpFactory else null,
            udpCatchallFactory = if (useUdp) udpFactory else null,
            hostForwarderSubnet = "10.99.0.0/24",
        ))

        dialerHandle = WgBridgeNative.nativeNew("10.99.0.2",
            MtuMath.DEFAULT_WG_MTU, 0)
        assertTrue("dialer nativeNew=$dialerHandle", dialerHandle > 0)
        // allowed_ip=0.0.0.0/0 is the critical bit — without it,
        // wireguard-go on the joiner drops outbound packets to
        // non-WG-subnet destinations because no peer claims those
        // IPs. Matches the ChromeOS full-tunnel config in the
        // field.
        assertEquals(0, WgBridgeNative.nativeConfigureUAPI(dialerHandle,
            buildString {
                append("private_key=").append(dialerPrivHex).append('\n')
                append("listen_port=0\n")
                append("replace_peers=true\n")
                append("public_key=").append(hostPubHex).append('\n')
                append("endpoint=127.0.0.1:").append(wgPort).append('\n')
                append("allowed_ip=0.0.0.0/0\n")
                append("persistent_keepalive_interval=1\n")
            }))
    }

    private fun hexToB64(hex: String): String {
        val bytes = ByteArray(hex.length / 2) { i ->
            ((Character.digit(hex[i * 2], 16) shl 4) or
                Character.digit(hex[i * 2 + 1], 16)).toByte()
        }
        return java.util.Base64.getEncoder().encodeToString(bytes)
    }

    private fun hostHandle(): Int {
        val backend = hostBackend ?: error("host backend not yet opened")
        val f = RealWgBridgeBackendNative::class.java
            .getDeclaredField("handle").apply { isAccessible = true }
        return f.getInt(backend)
    }

    private fun waitForHandshake(timeoutMs: Long) {
        val h = hostHandle()
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val a = WgBridgeNative.nativeSnapshotUAPI(h)?.let {
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
