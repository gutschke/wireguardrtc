package com.gutschke.wgrtc.data

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.SecureRandom

/**
 * **self-contained host-mode validation.**
 *
 * The slirp / QEMU NAT inside the container-hosted Android emulator
 * does not cleanly route an outbound response back through an
 * inbound port-forwarded mapping (verified empirically: outbound
 * UDP from the emulator's `:51820` arrives at the dev-container with
 * a randomised source port, not `:51820` — and the slirp NAT
 * does not preserve return paths for inbound-forwarded ports).
 * That makes [HostNativeHandshakeTest], which expects a sandbox
 * kernel-WG client to complete a handshake against the emulator,
 * an unreliable signal: it fails for environment reasons even
 * when the cgo path is correct.
 *
 * This test side-steps the network entirely. Two
 * `wgbridge_native` instances run in the SAME process — one
 * acting as host (), one as client (joiner pointed at
 * `127.0.0.1:<port>` with a persistent keepalive). All traffic
 * stays on the loopback so the slirp NAT never sees it. If
 * Go's wireguard-go and our cgo `//export` surface are
 * functioning correctly, both sides should complete a handshake
 * within ~3 s (one keepalive interval).
 *
 * If this test passes, is fundamentally sound and any
 * Pixel-9 spot-check failure is a real-network issue
 * (interface binding, firewall, MTU, ...). If it fails, we
 * have a deterministic on-emulator repro to iterate against.
 */
@RunWith(AndroidJUnit4::class)
class HostNativeSelfLoopTest {

    @Volatile private var hostHandle: Int = 0
    @Volatile private var clientHandle: Int = 0

    @After fun tearDown() {
        if (clientHandle > 0) {
            WgBridgeNative.nativeClose(clientHandle); clientHandle = 0
        }
        if (hostHandle > 0) {
            WgBridgeNative.nativeClose(hostHandle); hostHandle = 0
        }
    }

    @Test
    fun bothSidesCompleteHandshake() {
        // Generate two Curve25519 keypairs. wireguard-go's UAPI
        // wants the private key in hex; we derive the public
        // key from it via the SAME byte-clamping wireguard-go
        // applies internally so the two sides agree on
        // the public-key value.
        val (hostPriv, hostPub) = newKeyPair()
        val (cliPriv, cliPub) = newKeyPair()

        // Pick a high port that's unlikely to collide with
        // anything on the emulator (toybox netd usually doesn't
        // bind 51000+ ranges).
        val listenPort = 51000 + (SecureRandom().nextInt(500))

        // -- Host bridge () --------------------------------
        hostHandle = WgBridgeNative.nativeNew(
            localAddr = "10.99.0.1", mtu = 1420, listenPort = listenPort)
        assertTrue("host nativeNew=$hostHandle", hostHandle > 0)
        val hostUapi = buildString {
            append("private_key=").append(hostPriv).append('\n')
            append("listen_port=").append(listenPort).append('\n')
            append("replace_peers=true\n")
            append("public_key=").append(cliPub).append('\n')
            append("allowed_ip=10.99.0.2/32\n")
        }
        assertEquals(0, WgBridgeNative.nativeConfigureUAPI(hostHandle, hostUapi))

        // -- Client bridge (joiner) ------------------------------
        // listenPort=0 lets wireguard-go bind an ephemeral port —
        // the "client" side never receives unsolicited traffic.
        clientHandle = WgBridgeNative.nativeNew(
            localAddr = "10.99.0.2", mtu = 1420, listenPort = 0)
        assertTrue("client nativeNew=$clientHandle", clientHandle > 0)
        val clientUapi = buildString {
            append("private_key=").append(cliPriv).append('\n')
            // ephemeral listen_port — set to 0 explicitly so
            // wireguard-go doesn't keep its default of 0 (which
            // means "any" anyway, but be explicit).
            append("listen_port=0\n")
            append("replace_peers=true\n")
            append("public_key=").append(hostPub).append('\n')
            append("endpoint=127.0.0.1:").append(listenPort).append('\n')
            append("allowed_ip=10.99.0.1/32\n")
            // 1-second keepalive so the handshake is driven
            // immediately + retries fast on any drop.
            append("persistent_keepalive_interval=1\n")
        }
        assertEquals(0, WgBridgeNative.nativeConfigureUAPI(clientHandle, clientUapi))

        // Wait up to 5 s for either side to log a non-zero
        // last_handshake_time. wireguard-go logs on both peers
        // when handshake completes, and updates
        // last_handshake_time_sec on each side accordingly.
        val deadline = System.currentTimeMillis() + 5_000
        var hostShake: Long? = null
        var clientShake: Long? = null
        var lastHostDump: String? = null
        var lastClientDump: String? = null
        while (System.currentTimeMillis() < deadline) {
            lastHostDump = WgBridgeNative.nativeSnapshotUAPI(hostHandle)
            lastClientDump = WgBridgeNative.nativeSnapshotUAPI(clientHandle)
            hostShake = lastHostDump?.let { UapiStatsParser.parse(it).mostRecentHandshakeEpochMs }
            clientShake = lastClientDump?.let { UapiStatsParser.parse(it).mostRecentHandshakeEpochMs }
            if ((hostShake ?: 0L) > 0L && (clientShake ?: 0L) > 0L) return
            Thread.sleep(100)
        }
        android.util.Log.w("HostSelfLoopTest", "host UAPI:\n$lastHostDump")
        android.util.Log.w("HostSelfLoopTest", "client UAPI:\n$lastClientDump")
        org.junit.Assert.fail(
            "handshake did not complete on both sides within 5 s.\n" +
                "host shake=$hostShake clientShake=$clientShake\n" +
                "host UAPI: $lastHostDump\n" +
                "client UAPI: $lastClientDump")
    }

    /** Generate a (privateHex, publicHex) keypair compatible
     * with WireGuard / Curve25519. Done in Kotlin instead of
     * shelling out to `wg` because the emulator doesn't ship
     * the `wg` userspace tools. */
    private fun newKeyPair(): Pair<String, String> {
        val priv = ByteArray(32).apply { SecureRandom().nextBytes(this) }
        // wireguard's clamp:
        priv[0] = (priv[0].toInt() and 248).toByte()
        priv[31] = ((priv[31].toInt() and 127) or 64).toByte()
        // Compute scalar mult: pub = priv * basepoint(9, 0, ..., 0).
        // Use the bouncycastle / com.lambdaworks variant if
        // available; if not, fall back to libsodium via a pure-
        // Java reference (we ship neither, but Android API 24+
        // has javax.crypto KeyAgreement with X25519 since 30+).
        // The emulator runs API 33 so X25519 is present.
        val kf = java.security.KeyFactory.getInstance("XDH")
        val privSpec = java.security.spec.PKCS8EncodedKeySpec(
            wrapPrivateAsPkcs8(priv))
        val privKey = kf.generatePrivate(privSpec)
        val ka = javax.crypto.KeyAgreement.getInstance("XDH")
        ka.init(privKey)
        // Use the basepoint (9 followed by zeros) as the peer
        // pub-key spec to derive priv*basepoint = pub.
        val base = ByteArray(32); base[0] = 9
        val basePub = kf.generatePublic(
            java.security.spec.X509EncodedKeySpec(wrapPublicAsX509(base)))
        ka.doPhase(basePub, true)
        val pub = ka.generateSecret()
        return hex(priv) to hex(pub)
    }

    /** Wrap raw 32-byte X25519 private key as PKCS#8. Header bytes
     * are the ASN.1 OID + structure for `id-X25519`, taken from
     * RFC 8410 §7. */
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
