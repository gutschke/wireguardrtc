package com.gutschke.wgrtc.data

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.SecureRandom
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * **end-to-end host listener test.**
 *
 * Validates that a host-mode bridge (gvisor netstack) can accept
 * an inbound TCP connection from a peer dialled in through WG, +
 * round-trip an arbitrary payload. Same self-loop topology as
 * [HostNativeSelfLoopTest] (two `wgbridge_native` instances in
 * one process talking via loopback) so the slirp NAT artifact
 * from the emulator can't interfere.
 *
 * Topology:
 *
 * ┌──────────────────────┐ ┌──────────────────────┐
 * │ host bridge │ WG handshake │ "dialer" bridge │
 * │ netstack 10.99.0.1 │ ──────────────→│ netstack 10.99.0.2 │
 * │ listenPort = X │ ←──────────────│ endpoint = 127.0.0.1:X
 * │ ListenTCP(:8080) │ │ DialTCP("10.99.0.1:8080")
 * └──────────────────────┘ └──────────────────────┘
 *
 * Steps:
 * 1. Open both bridges + configure UAPI with each other as peers.
 * 2. Host opens a TCP listener with an echo acceptor (reads N
 * bytes, writes them back, closes).
 * 3. Dialer DialTCP's the host's listen address. Once the
 * acceptor fires, we have a live connection both sides.
 * 4. Dialer writes a random 64-byte payload.
 * 5. Acceptor reads it and echoes back.
 * 6. Dialer reads the echo; we compare byte-for-byte.
 */
@RunWith(AndroidJUnit4::class)
class HostNativeListenerTest {

    @Volatile private var hostHandle: Int = 0
    @Volatile private var dialerHandle: Int = 0
    @Volatile private var listenerId: Int = 0
    @Volatile private var dialerConnId: Int = 0

    @After fun tearDown() {
        if (dialerConnId > 0) {
            try { WgBridgeNative.nativeTcpClose(dialerConnId) } catch (_: Throwable) {}
            dialerConnId = 0
        }
        if (listenerId > 0) {
            try { WgBridgeNative.nativeCloseListener(listenerId) } catch (_: Throwable) {}
            TcpListenerRegistry.unregister(listenerId)
            listenerId = 0
        }
        if (dialerHandle > 0) {
            WgBridgeNative.nativeClose(dialerHandle); dialerHandle = 0
        }
        if (hostHandle > 0) {
            WgBridgeNative.nativeClose(hostHandle); hostHandle = 0
        }
    }

    @Test
    fun echoOverHostTcpListener() {
        // ── Generate keypairs ────────────────────────────────────
        val (hostPriv, hostPub) = newKeyPair()
        val (dialerPriv, dialerPub) = newKeyPair()
        val wgPort = 51000 + SecureRandom().nextInt(500)
        val servicePort = 8080

        // ── Bridge A: host ───────────────────────────────────────
        hostHandle = WgBridgeNative.nativeNew(
            localAddr = "10.99.0.1", mtu = 1420, listenPort = wgPort)
        assertTrue("host nativeNew=$hostHandle", hostHandle > 0)
        val hostUapi = buildString {
            append("private_key=").append(hostPriv).append('\n')
            append("listen_port=").append(wgPort).append('\n')
            append("replace_peers=true\n")
            append("public_key=").append(dialerPub).append('\n')
            append("allowed_ip=10.99.0.2/32\n")
        }
        assertEquals(0, WgBridgeNative.nativeConfigureUAPI(hostHandle, hostUapi))

        // ── Bridge B: dialer ─────────────────────────────────────
        dialerHandle = WgBridgeNative.nativeNew(
            localAddr = "10.99.0.2", mtu = 1420, listenPort = 0)
        assertTrue("dialer nativeNew=$dialerHandle", dialerHandle > 0)
        val dialerUapi = buildString {
            append("private_key=").append(dialerPriv).append('\n')
            append("listen_port=0\n")
            append("replace_peers=true\n")
            append("public_key=").append(hostPub).append('\n')
            append("endpoint=127.0.0.1:").append(wgPort).append('\n')
            append("allowed_ip=10.99.0.1/32\n")
            append("persistent_keepalive_interval=1\n")
        }
        assertEquals(0, WgBridgeNative.nativeConfigureUAPI(dialerHandle, dialerUapi))

        // ── Wait for the WG handshake to complete on both sides ──
        waitForHandshake(timeoutMs = 5_000)

        // ── Host opens an echo TCP listener ──────────────────────
        // The acceptor enqueues each accepted connection on this
        // queue so the test thread can synchronise with it.
        val accepted = LinkedBlockingQueue<WgTcpHandle>()
        val acceptor = object : WgTcpAcceptor {
            override fun onAccept(peerAddr: String, listenAddr: String, conn: WgTcpHandle) {
                accepted.put(conn)
                // Echo on a dedicated thread so onAccept returns
                // immediately (the native dispatcher needs to
                // detach quickly).
                Thread({
                    val buf = ByteArray(256)
                    while (true) {
                        val n = conn.read(buf)
                        if (n <= 0) break
                        // Slice off the bytes we actually got so
                        // the write doesn't echo trailing zeros.
                        val out = if (n == buf.size) buf else buf.copyOf(n)
                        try { conn.write(out) } catch (_: Throwable) { break }
                    }
                    try { conn.close() } catch (_: Throwable) {}
                }, "host-echo-worker").start()
            }
        }
        listenerId = WgBridgeNative.nativeListenTcp(hostHandle, servicePort)
        assertTrue("nativeListenTcp=$listenerId", listenerId > 0)
        TcpListenerRegistry.register(listenerId, acceptor)

        // ── Dialer connects via WG to 10.99.0.1:8080 ─────────────
        dialerConnId = WgBridgeNative.nativeDialTcp(
            dialerHandle, "10.99.0.1:$servicePort")
        assertTrue("nativeDialTcp=$dialerConnId", dialerConnId > 0)

        // Wait until the host saw the accept callback so we know
        // the acceptor + echo worker are wired up.
        val hostConn = accepted.poll(3, TimeUnit.SECONDS)
        assertNotEquals(null, hostConn)

        // ── Send a random 64-byte payload + expect an echo back ──
        val payload = ByteArray(64).also { SecureRandom().nextBytes(it) }
        // Use the dialer's connection. These calls go via
        // WgBridgeNative.nativeTcpRead/Write directly — same wire
        // protocol the WgTcpHandleNative wrapper uses internally.
        val written = WgBridgeNative.nativeTcpWrite(dialerConnId, payload, payload.size)
        assertEquals(payload.size, written)

        val rxBuf = ByteArray(payload.size)
        var rxOffset = 0
        val deadline = System.currentTimeMillis() + 3_000
        while (rxOffset < payload.size && System.currentTimeMillis() < deadline) {
            // Read into a slice covering remaining bytes. The
            // native read fills from offset 0 each call, so
            // accumulate via a per-call temp buffer.
            val tmp = ByteArray(payload.size - rxOffset)
            val n = WgBridgeNative.nativeTcpRead(dialerConnId, tmp, tmp.size)
            if (n <= 0) break
            System.arraycopy(tmp, 0, rxBuf, rxOffset, n)
            rxOffset += n
        }
        assertEquals("expected ${payload.size} bytes of echo back", payload.size, rxOffset)
        assertArrayEquals("echo payload mismatch", payload, rxBuf)
    }

    /** Poll both bridges' UAPI snapshots until each peer's
     * last_handshake_time_sec > 0, or fail. */
    private fun waitForHandshake(timeoutMs: Long) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val hostDump = WgBridgeNative.nativeSnapshotUAPI(hostHandle)
            val dialerDump = WgBridgeNative.nativeSnapshotUAPI(dialerHandle)
            val hostMs = hostDump?.let { UapiStatsParser.parse(it).mostRecentHandshakeEpochMs }
            val dialerMs = dialerDump?.let { UapiStatsParser.parse(it).mostRecentHandshakeEpochMs }
            if ((hostMs ?: 0L) > 0L && (dialerMs ?: 0L) > 0L) return
            Thread.sleep(100)
        }
        throw AssertionError("handshake did not complete within $timeoutMs ms")
    }

    /** Generate a (privHex, pubHex) Curve25519 keypair. Same
     * helper [HostNativeSelfLoopTest] uses; copied to avoid
     * cross-test coupling. */
    private fun newKeyPair(): Pair<String, String> {
        val priv = ByteArray(32).apply { SecureRandom().nextBytes(this) }
        priv[0] = (priv[0].toInt() and 248).toByte()
        priv[31] = ((priv[31].toInt() and 127) or 64).toByte()
        val kf = java.security.KeyFactory.getInstance("XDH")
        val privSpec = java.security.spec.PKCS8EncodedKeySpec(wrapPrivateAsPkcs8(priv))
        val privKey = kf.generatePrivate(privSpec)
        val ka = javax.crypto.KeyAgreement.getInstance("XDH")
        ka.init(privKey)
        val base = ByteArray(32); base[0] = 9
        val basePub = kf.generatePublic(java.security.spec.X509EncodedKeySpec(wrapPublicAsX509(base)))
        ka.doPhase(basePub, true)
        val pub = ka.generateSecret()
        return hex(priv) to hex(pub)
    }

    private fun wrapPrivateAsPkcs8(raw: ByteArray): ByteArray {
        require(raw.size == 32)
        val header = byteArrayOf(
            0x30, 0x2e, 0x02, 0x01, 0x00,
            0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
            0x04, 0x22, 0x04, 0x20)
        return header + raw
    }

    private fun wrapPublicAsX509(raw: ByteArray): ByteArray {
        require(raw.size == 32)
        val header = byteArrayOf(
            0x30, 0x2a,
            0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
            0x03, 0x21, 0x00)
        return header + raw
    }

    private fun hex(b: ByteArray): String =
        StringBuilder(64).apply {
            for (x in b) append("%02x".format(x.toInt() and 0xff))
        }.toString()
}
