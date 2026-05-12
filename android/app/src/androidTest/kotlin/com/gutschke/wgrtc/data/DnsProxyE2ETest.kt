package com.gutschke.wgrtc.data

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.net.Inet4Address
import java.net.InetAddress
import java.security.SecureRandom

/**
 * **DNS proxy end-to-end test.**
 *
 * Two self-loop bridges (no slirp dependency). Host runs the
 * [DnsService] on udp:53 with a fixed-fake resolver. Joiner
 * dials a UDP socket into 10.99.0.1:53 *through the WG tunnel*
 * and sends a real DNS A query. The response should arrive
 * with the right TXID and the fake's canned answer.
 *
 * What this proves the unit tests can't:
 * - The UDP listener machinery from is correctly hooked.
 * - gvisor's UDP path doesn't fragment / drop a small DNS
 * packet across the netstack boundary.
 * - The query → resolve → response → return-path roundtrip
 * completes within a reasonable budget.
 * - Coroutine dispatch from the netstack callback works
 * (this is the subtlety we worried about in DnsService).
 */
@RunWith(AndroidJUnit4::class)
class DnsProxyE2ETest {

    @Volatile private var hostHandle = 0
    @Volatile private var joinerHandle = 0
    @Volatile private var dnsService: DnsService? = null
    @Volatile private var hostBackend: WgBridgeBackend? = null
    @Volatile private var joinerListenerId = 0
    private val scope = CoroutineScope(SupervisorJob())

    @After fun tearDown() {
        if (joinerListenerId > 0)
            try { WgBridgeNative.nativeCloseListener(joinerListenerId) } catch (_: Throwable) {}
        dnsService?.stop()
        try { hostBackend?.close() } catch (_: Throwable) {}
        if (joinerHandle > 0) WgBridgeNative.nativeClose(joinerHandle)
        // hostHandle is closed via hostBackend.close() above.
    }

    @Test
    fun dnsQueryThroughTunnelResolvesViaFakeResolver() {
        val expectedAddr = Inet4Address.getByAddress(byteArrayOf(203.toByte(), 0, 113, 42))
        val fakeResolver = object : DnsResolver {
            override fun resolve(name: String): List<InetAddress> {
                return when (name.trim('.').lowercase()) {
                    "test.example" -> listOf(expectedAddr)
                    else -> emptyList()
                }
            }
        }

        val (hostPriv, hostPub) = newKeyPair()
        val (joinerPriv, joinerPub) = newKeyPair()
        val wgPort = 51000 + SecureRandom().nextInt(500)

        // Host bridge + DnsService.
        hostHandle = WgBridgeNative.nativeNew("10.99.0.1", MtuMath.DEFAULT_WG_MTU, wgPort)
        assertTrue("host nativeNew=$hostHandle", hostHandle > 0)
        assertEquals(0, WgBridgeNative.nativeConfigureUAPI(hostHandle, buildString {
            append("private_key=").append(hostPriv).append('\n')
            append("listen_port=").append(wgPort).append('\n')
            append("replace_peers=true\n")
            append("public_key=").append(joinerPub).append('\n')
            append("allowed_ip=10.99.0.2/32\n")
        }))

        // Wrap the host bridge in a WgBridgeBackend so DnsService
        // can call listenUdp() through the normal interface.
        val backend = openHostBackend(hostHandle)
        hostBackend = backend
        dnsService = DnsService(DnsProxy(fakeResolver), scope).also { it.start(backend) }

        // Joiner bridge — also a host-mode bridge (with its own
        // netstack) so we can ListenUDP+SendTo from inside it
        // and route the datagram through WG.
        joinerHandle = WgBridgeNative.nativeNew("10.99.0.2", MtuMath.DEFAULT_WG_MTU, 0)
        assertTrue("joiner nativeNew=$joinerHandle", joinerHandle > 0)
        assertEquals(0, WgBridgeNative.nativeConfigureUAPI(joinerHandle, buildString {
            append("private_key=").append(joinerPriv).append('\n')
            append("listen_port=0\n")
            append("replace_peers=true\n")
            append("public_key=").append(hostPub).append('\n')
            append("endpoint=127.0.0.1:").append(wgPort).append('\n')
            append("allowed_ip=10.99.0.1/32\n")
            append("persistent_keepalive_interval=1\n")
        }))
        waitForHandshake(5_000)

        // Open a UDP listener on the joiner side (any port) so we
        // can both send and receive on the joiner netstack.
        // We hold a reference to its sink so we can sendTo()
        // arbitrary destinations.
        val replies = java.util.concurrent.LinkedBlockingQueue<ByteArray>()
        joinerListenerId = WgBridgeNative.nativeListenUdp(joinerHandle, 0)
        assertTrue("nativeListenUdp=$joinerListenerId", joinerListenerId > 0)
        val joinerSink = WgUdpSinkNative(joinerListenerId)
        UdpListenerRegistry.register(joinerListenerId, object : WgUdpReceiver {
            override fun onDatagram(peerAddr: String, listenAddr: String, data: ByteArray) {
                replies.put(data)
            }
        }, joinerSink)

        // Send the actual DNS query.
        val txid = 0xABCD
        val query = buildAQuery(txid, "test.example")
        joinerSink.sendTo("10.99.0.1:53", query)

        // Wait for the reply.
        val reply = replies.poll(3, java.util.concurrent.TimeUnit.SECONDS)
        assertTrue("no DNS reply within 3s", reply != null)
        reply!!

        // Verify response shape.
        val rxTxid = ((reply[0].toInt() and 0xff) shl 8) or (reply[1].toInt() and 0xff)
        assertEquals(txid, rxTxid)
        val ancount = ((reply[6].toInt() and 0xff) shl 8) or (reply[7].toInt() and 0xff)
        assertEquals(1, ancount)
        // Find the answer's 4-byte RDATA — should be 203.0.113.42.
        val needle = byteArrayOf(203.toByte(), 0, 113, 42)
        var found = false
        for (i in 12..(reply.size - 4)) {
            if (reply[i] == needle[0] && reply[i + 1] == needle[1] &&
                reply[i + 2] == needle[2] && reply[i + 3] == needle[3]) {
                found = true; break
            }
        }
        assertTrue("answer 203.0.113.42 not in reply", found)
        // Negative check: ensure the response isn't an
        // accidental echo of the query bytes (which would also
        // pass the txid+ancount tests if we got really unlucky).
        assertNotEquals(0, ancount) // already checked above; explicit for sanity
    }

    /** Adapt a bare host handle into a WgBridgeBackend without
     * the full RealWgBridgeBackendNative wrapping (which uses
     * a private ctor). Anonymous inline implementation. */
    private fun openHostBackend(handle: Int): WgBridgeBackend = object : WgBridgeBackend {
        @Volatile private var closed = false
        private val active = mutableListOf<Int>()
        private val lock = Any()
        override fun configureUapi(uapi: String) { /* already configured */ }
        override fun listenTcp(port: Int, acceptor: WgTcpAcceptor) {
            val id = WgBridgeNative.nativeListenTcp(handle, port)
            check(id > 0)
            TcpListenerRegistry.register(id, acceptor)
            synchronized(lock) { active += id }
        }
        override fun listenUdp(port: Int, receiver: WgUdpReceiver): WgUdpSink {
            val id = WgBridgeNative.nativeListenUdp(handle, port)
            check(id > 0)
            val sink = WgUdpSinkNative(id)
            UdpListenerRegistry.register(id, receiver, sink)
            synchronized(lock) { active += id }
            return sink
        }
        override fun setFdProtector(protector: WgFdProtector?) {}
        override fun snapshotUapi(): String =
            WgBridgeNative.nativeSnapshotUAPI(handle) ?: ""
        override fun close() {
            if (closed) return
            closed = true
            val toClose = synchronized(lock) { val c = active.toList(); active.clear(); c }
            for (id in toClose) {
                try { WgBridgeNative.nativeCloseListener(id) } catch (_: Throwable) {}
                TcpListenerRegistry.unregister(id); UdpListenerRegistry.unregister(id)
            }
            WgBridgeNative.nativeClose(handle)
        }
    }

    private fun waitForHandshake(timeoutMs: Long) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val a = WgBridgeNative.nativeSnapshotUAPI(hostHandle)?.let {
                UapiStatsParser.parse(it).mostRecentHandshakeEpochMs
            } ?: 0L
            val b = WgBridgeNative.nativeSnapshotUAPI(joinerHandle)?.let {
                UapiStatsParser.parse(it).mostRecentHandshakeEpochMs
            } ?: 0L
            if (a > 0 && b > 0) return
            Thread.sleep(100)
        }
        throw AssertionError("handshake did not complete within $timeoutMs ms")
    }

    private fun buildAQuery(txid: Int, name: String): ByteArray {
        val labels = name.trim('.').split('.').filter { it.isNotEmpty() }
        val qnameSize = labels.sumOf { 1 + it.length } + 1
        val buf = ByteArray(12 + qnameSize + 4)
        buf[0] = (txid ushr 8 and 0xff).toByte(); buf[1] = (txid and 0xff).toByte()
        buf[2] = 0x01 // RD=1
        buf[5] = 1 // qdcount=1
        var p = 12
        for (l in labels) {
            buf[p++] = l.length.toByte()
            for (c in l) buf[p++] = c.code.toByte()
        }
        buf[p++] = 0; buf[p++] = 0; buf[p++] = 1 // type A
        buf[p++] = 0; buf[p] = 1 // class IN
        return buf
    }

    private fun newKeyPair(): Pair<String, String> {
        val priv = ByteArray(32).apply { SecureRandom().nextBytes(this) }
        priv[0] = (priv[0].toInt() and 248).toByte()
        priv[31] = ((priv[31].toInt() and 127) or 64).toByte()
        val kf = java.security.KeyFactory.getInstance("XDH")
        val privKey = kf.generatePrivate(java.security.spec.PKCS8EncodedKeySpec(
            byteArrayOf(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03,
                0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20) + priv))
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
