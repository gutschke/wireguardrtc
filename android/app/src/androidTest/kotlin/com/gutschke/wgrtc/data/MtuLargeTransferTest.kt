package com.gutschke.wgrtc.data

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * **large-transfer MTU validation.**
 *
 * Pushes a multi-megabyte payload through a self-loop pair of
 * `wgbridge_native` bridges to exercise gvisor's TCP
 * segmentation + reassembly at MTU boundaries. An MTU misconfig
 * (or a missing MSS clamp) typically shows up here as either:
 *
 * - A hang (handshake works, small packets work, big ones get
 * silently dropped — the classic PMTU black hole symptom).
 * - A byte-corruption (re-segmentation produced wrong content).
 *
 * Both are catastrophic for the NAT-mode user experience.
 *
 * **Volume.** 4 MiB. Big enough to force tens of thousands of
 * TCP segments at the default MSS but small enough to keep the
 * test under ~5s on the emulator. A SHA-256 over the round-trip
 * bytes catches any corruption that survives a length match.
 */
@RunWith(AndroidJUnit4::class)
class MtuLargeTransferTest {

    @Volatile private var hostHandle = 0
    @Volatile private var dialerHandle = 0
    @Volatile private var listenerId = 0
    @Volatile private var dialerConnId = 0

    @After fun tearDown() {
        if (dialerConnId > 0) try { WgBridgeNative.nativeTcpClose(dialerConnId) } catch (_: Throwable) {}
        if (listenerId > 0) {
            try { WgBridgeNative.nativeCloseListener(listenerId) } catch (_: Throwable) {}
            TcpListenerRegistry.unregister(listenerId)
        }
        if (dialerHandle > 0) WgBridgeNative.nativeClose(dialerHandle)
        if (hostHandle > 0) WgBridgeNative.nativeClose(hostHandle)
    }

    @Test
    fun fourMiBTransferRoundTripsByteIdenticalThroughGvisorTcp() {
        val payloadSize = 4 * 1024 * 1024 // 4 MiB
        val (hostPriv, hostPub) = newKeyPair()
        val (dialerPriv, dialerPub) = newKeyPair()
        val wgPort = 51000 + SecureRandom().nextInt(500)
        val servicePort = 9090

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

        // Acceptor: read N bytes, echo them back, close. Uses
        // a separate worker thread so onAccept returns quickly.
        val accepted = LinkedBlockingQueue<WgTcpHandle>()
        listenerId = WgBridgeNative.nativeListenTcp(hostHandle, servicePort)
        assertTrue(listenerId > 0)
        TcpListenerRegistry.register(listenerId, object : WgTcpAcceptor {
            override fun onAccept(peerAddr: String, listenAddr: String, conn: WgTcpHandle) {
                accepted.put(conn)
                Thread({
                    // Echo loop. Read into a buffer, write back
                    // the same byte count. Sized to a comfortable
                    // multiple of the MSS — too small and we
                    // syscall-bottleneck the test, too large and
                    // we hide latency-related corruption.
                    val buf = ByteArray(64 * 1024)
                    while (true) {
                        val n = conn.read(buf)
                        if (n <= 0) break
                        val out = if (n == buf.size) buf else buf.copyOf(n)
                        try { conn.write(out) } catch (_: Throwable) { break }
                    }
                    try { conn.close() } catch (_: Throwable) {}
                }, "echo-worker").start()
            }
        })

        dialerConnId = WgBridgeNative.nativeDialTcp(dialerHandle, "10.99.0.1:$servicePort")
        assertTrue("nativeDialTcp=$dialerConnId", dialerConnId > 0)
        val hostConn = accepted.poll(3, TimeUnit.SECONDS)
        assertTrue("acceptor never fired", hostConn != null)

        // ── Generate payload, write it, read it back ──────────
        val payload = ByteArray(payloadSize).also { SecureRandom().nextBytes(it) }
        val expectedHash = sha256(payload)

        // Writer thread — push the whole payload in chunks.
        val writerErr = arrayOfNulls<Throwable>(1)
        val writer = Thread({
            try {
                val chunk = 64 * 1024
                var off = 0
                while (off < payload.size) {
                    val n = minOf(chunk, payload.size - off)
                    val slice = payload.copyOfRange(off, off + n)
                    val written = WgBridgeNative.nativeTcpWrite(dialerConnId, slice, n)
                    if (written < 0) throw AssertionError("write rc=$written at off=$off")
                    if (written == 0) throw AssertionError("zero-byte write at off=$off")
                    off += written
                }
            } catch (t: Throwable) {
                writerErr[0] = t
            }
        }, "tx").apply { start() }

        // Reader (main thread) — accumulate up to payloadSize.
        val rxHash = MessageDigest.getInstance("SHA-256")
        val rxBuf = ByteArray(64 * 1024)
        var rxTotal = 0
        val deadline = System.currentTimeMillis() + 30_000
        while (rxTotal < payloadSize && System.currentTimeMillis() < deadline) {
            val n = WgBridgeNative.nativeTcpRead(dialerConnId, rxBuf, rxBuf.size)
            if (n < 0) throw AssertionError("read rc=$n after $rxTotal bytes")
            if (n == 0) break // unexpected EOF
            rxHash.update(rxBuf, 0, n)
            rxTotal += n
        }
        writer.join(5_000)
        writerErr[0]?.let { throw it }

        assertEquals("byte count mismatch", payloadSize, rxTotal)
        assertArrayEquals(
            "SHA-256 mismatch (corruption in segmentation / reassembly)",
            expectedHash, rxHash.digest()
        )
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

    private fun sha256(b: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").apply { update(b) }.digest()

    private fun newKeyPair(): Pair<String, String> {
        val priv = ByteArray(32).apply { SecureRandom().nextBytes(this) }
        priv[0] = (priv[0].toInt() and 248).toByte()
        priv[31] = ((priv[31].toInt() and 127) or 64).toByte()
        val kf = java.security.KeyFactory.getInstance("XDH")
        val privKey = kf.generatePrivate(java.security.spec.PKCS8EncodedKeySpec(
            byteArrayOf(0x30, 0x2e, 0x02, 0x01, 0x00,
                0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
                0x04, 0x22, 0x04, 0x20) + priv))
        val ka = javax.crypto.KeyAgreement.getInstance("XDH").apply { init(privKey) }
        val base = ByteArray(32).also { it[0] = 9 }
        val basePub = kf.generatePublic(java.security.spec.X509EncodedKeySpec(
            byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
                0x03, 0x21, 0x00) + base))
        ka.doPhase(basePub, true)
        val pub = ka.generateSecret()
        fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        return hex(priv) to hex(pub)
    }
}
