package com.gutschke.wgrtc.data

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicReference

/**
 * **catchall TCP forwarder end-to-end test.**
 *
 * Validates the full userspace-NAT flow:
 *
 * 1. A real TCP echo server runs on the test JVM's loopback,
 * port assigned by the OS.
 * 2. A host-mode bridge runs gvisor netstack at 10.99.0.1 with
 * [wgbridgeInstallTCPForwarder].
 * 3. A joiner-mode bridge (also a host-mode bridge, used as
 * a dialer here) sits at 10.99.0.2 + targets the host via
 * WG.
 * 4. After handshake, joiner's netstack dials
 * `127.0.0.1:echoPort` *through the WG tunnel*. The host's
 * forwarder catches the SYN, the Kotlin handler resolves
 * (identity), opens an OS socket to the echo server, and
 * `TcpFlowForwarder` pumps bytes both ways.
 * 5. Round-trip a 1 KiB random payload + verify byte-identical.
 *
 * This is the headline NAT test. If it passes, the architectural
 * claim "your ChromeOS sees the phone as the gateway" is no
 * longer aspirational — it's wired up.
 */
@RunWith(AndroidJUnit4::class)
class NatTcpForwarderE2ETest {

    @Volatile private var hostHandle = 0
    @Volatile private var dialerHandle = 0
    @Volatile private var forwarderId = 0
    @Volatile private var dialerConnId = 0
    @Volatile private var echoServer: ServerSocket? = null
    @Volatile private var echoThread: Thread? = null
    private val scope = CoroutineScope(SupervisorJob())

    @After fun tearDown() {
        if (dialerConnId > 0)
            try { WgBridgeNative.nativeTcpClose(dialerConnId) } catch (_: Throwable) {}
        if (forwarderId > 0) {
            try { WgBridgeNative.nativeCloseListener(forwarderId) } catch (_: Throwable) {}
            TcpForwarderRegistry.unregister(forwarderId)
        }
        if (dialerHandle > 0) WgBridgeNative.nativeClose(dialerHandle)
        if (hostHandle > 0) WgBridgeNative.nativeClose(hostHandle)
        try { echoServer?.close() } catch (_: Throwable) {}
        echoThread?.interrupt()
        scope.cancel()
    }

    @Test
    fun joinerDialOnArbitraryPortReachesEchoServerViaForwarder() {
        // ── Spin up a real echo server on the test JVM ──────────
        val server = ServerSocket(0, /* backlog */ 4,
            InetAddress.getByName("127.0.0.1"))
        echoServer = server
        val echoPort = server.localPort
        echoThread = Thread({
            try {
                while (!server.isClosed) {
                    val c = try { server.accept() } catch (_: Throwable) { break }
                    Thread({ echoLoop(c) }, "echo-conn").start()
                }
            } catch (_: Throwable) { /* tear-down */ }
        }, "echo-srv").apply { start() }

        // ── Stand up the two bridges + complete handshake ───────
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

        // ── Install the catchall forwarder on the host bridge ───
        val handler = TcpForwarderHandler(
            // The joiner dials 10.99.0.1:<echoPort> (because
            // that's the WG-side address it can route to). The
            // forwarder catches the SYN with origDest set to
            // that. But the echo server actually lives on the
            // host's real loopback (127.0.0.1:echoPort) — the
            // WG-side 10.99.0.1 is a netstack-only fiction. In
            // production a similar mapping happens: the joiner
            // dials some IP and the host's resolver decides
            // where to actually connect (often identity to the
            // joiner's intended IP, but sometimes a remap).
            targetResolver = { _, origDest ->
                val (_, p) = parseHostPort(origDest)
                java.net.InetSocketAddress("127.0.0.1", p)
            },
        )
        forwarderId = WgBridgeNative.nativeInstallTcpForwarder(hostHandle)
        assertTrue("nativeInstallTcpForwarder=$forwarderId", forwarderId > 0)
        TcpForwarderRegistry.register(forwarderId, handler, scope)

        // ── Joiner dials through the WG tunnel ──────────────────
        // The destination is the echo server's port on 127.0.0.1
        // FROM THE HOST'S PERSPECTIVE — but the joiner phrases
        // the request as "10.99.0.1's view of 127.0.0.1" which
        // is just "127.0.0.1" in the destination IP field. The
        // joiner's netstack routes any address through the
        // 10.99.0.1/32 allowedip → WG tunnel.
        //
        // We can't actually dial 127.0.0.1:echoPort from the
        // joiner side, because the joiner's wg-quick allowed_ip
        // is 10.99.0.1/32 — only that address routes through
        // the tunnel. So dial 10.99.0.1:echoPort instead; the
        // host's forwarder catches *any* destination address
        // (gvisor delivers all SYNs to the protocol handler
        // regardless of address), so it works.
        dialerConnId = WgBridgeNative.nativeDialTcp(
            dialerHandle, "10.99.0.1:$echoPort")
        assertTrue("nativeDialTcp=$dialerConnId", dialerConnId > 0)

        // ── Round-trip a payload ────────────────────────────────
        val payload = ByteArray(1024).also { SecureRandom().nextBytes(it) }
        val written = WgBridgeNative.nativeTcpWrite(
            dialerConnId, payload, payload.size)
        assertEquals(payload.size, written)

        val rxBuf = ByteArray(payload.size)
        var rxOffset = 0
        val deadline = System.currentTimeMillis() + 5_000
        while (rxOffset < payload.size && System.currentTimeMillis() < deadline) {
            val tmp = ByteArray(payload.size - rxOffset)
            val n = WgBridgeNative.nativeTcpRead(dialerConnId, tmp, tmp.size)
            if (n <= 0) break
            System.arraycopy(tmp, 0, rxBuf, rxOffset, n)
            rxOffset += n
        }
        assertEquals(payload.size, rxOffset)
        assertArrayEquals(
            "echoed bytes differ from sent (NAT corruption?)",
            payload, rxBuf
        )
    }

    private fun echoLoop(c: Socket) {
        try {
            val ins = c.getInputStream()
            val outs = c.getOutputStream()
            val buf = ByteArray(8192)
            while (true) {
                val n = ins.read(buf)
                if (n <= 0) break
                outs.write(buf, 0, n)
                outs.flush()
            }
        } catch (_: Throwable) { /* connection done */ }
        try { c.close() } catch (_: Throwable) {}
    }

    private fun parseHostPort(s: String): Pair<String, Int> {
        val colon = s.lastIndexOf(':')
        val host = s.substring(0, colon).trim('[', ']')
        val port = s.substring(colon + 1).toInt()
        return host to port
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
