package com.gutschke.wgrtc.data

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import java.security.SecureRandom

/**
 * **ICMPv4 ping round-trip through the WG tunnel.**
 *
 * Self-loop topology, same as the other Nat*E2ETests:
 *
 * joiner bridge (10.99.0.2) ←──── WG ────→ host bridge (10.99.0.1)
 *
 * We exercise `nativePingV4` on the joiner side targeting
 * `10.99.0.1`. gvisor's netstack on the host auto-replies to
 * any ICMP echo request aimed at an address it owns, so this
 * round-trip works *without any custom ICMP forwarder* installed
 * on the host.
 *
 * The point of the test isn't to prove the gvisor library works
 * (it does); it's to nail down that the wire path from a peer's
 * application-layer ping → WG encrypt → tunnel → WG decrypt →
 * netstack ICMP handler → reply → reverse path → peer's reader
 * is unbroken. Any future regression that breaks ICMP traffic
 * over the tunnel — typically a packet-filter, MTU, or routing
 * bug — surfaces here.
 *
 * Validates:
 *
 * - First echo request succeeds (positive RTT)
 * - RTT is reasonable for an emulator self-loop (< 1 s)
 * - A second ping on the same bridges still works (no
 * endpoint-leak / one-shot artifact)
 *
 * **Out of scope.** ICMP forwarding from the joiner to addresses
 * *outside* the netstack (the joiner pings 8.8.8.8 through the
 * tunnel and the host forwards to the public internet) is
 * documented as a future enhancement in `icmp.go`'s kdoc.
 */
@RunWith(AndroidJUnit4::class)
class NatIcmpPingE2ETest {

    @Volatile private var hostHandle = 0
    @Volatile private var dialerHandle = 0

    @After fun tearDown() {
        if (dialerHandle > 0) WgBridgeNative.nativeClose(dialerHandle)
        if (hostHandle > 0) WgBridgeNative.nativeClose(hostHandle)
    }

    @Test
    fun joinerPingsHostWgSideAddressRoundTrip() {
        val (hostPriv, hostPub) = newKeyPair()
        val (dialerPriv, dialerPub) = newKeyPair()
        val wgPort = 51500 + SecureRandom().nextInt(500)

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

        // First ping — RTT in microseconds.
        val rtt1Us = WgBridgeNative.nativePingV4(dialerHandle, "10.99.0.1", 3_000)
        assertTrue("first ping returned negative rc=$rtt1Us " +
            "(see icmp.go for codes)", rtt1Us >= 0)
        // 1 s upper bound — anything more is a regression we should
        // notice. Local emulator typically reports < 100 ms.
        assertTrue("first ping RTT=${rtt1Us}us suspiciously slow",
            rtt1Us < 1_000_000)

        // Second ping — confirms the netstack ICMP path isn't
        // a one-shot.
        val rtt2Us = WgBridgeNative.nativePingV4(dialerHandle, "10.99.0.1", 3_000)
        assertTrue("second ping returned negative rc=$rtt2Us", rtt2Us >= 0)
        assertTrue("second ping RTT=${rtt2Us}us suspiciously slow",
            rtt2Us < 1_000_000)
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
