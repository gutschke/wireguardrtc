package com.gutschke.wgrtc.data

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.SecureRandom

/**
 * Proof-of-concept: a single Android device can run **two
 * concurrent wgbridge_native host instances** in one Go runtime.
 *
 * Motivation: the app's higher-level `HostModeBackend` enforces a
 * single active host tunnel at a time (an explicit `check(activeId
 * == null)` at the entry of `start()`).  That restriction is an
 * app-level artifact, not a wgbridge_native or wireguard-go
 * limitation — see `wgbridge_native/api.go`, where `bridges` is a
 * `map[int32]*bridgeState` keyed by per-instance handles.  The
 * companion test `HostNativeSelfLoopTest` already exercises two
 * instances (one acting as host, one as client) coexisting; this
 * test proves the **two-host** case, which is the building block
 * for any future "single phone hosting two distinct wgrtc tunnels"
 * feature.
 *
 * Concretely we:
 *
 *  1. Open two `wgbridgeNew` instances (different listen ports,
 *     different /24 subnets).
 *  2. Configure each with its own private key + a stub peer entry.
 *  3. Confirm both report non-empty UAPI snapshots and that the
 *     snapshots reflect *independent* peer tables.
 *
 * What this test does NOT validate:
 *  - End-to-end packet flow between two host instances on the
 *    same device — they would need a router (or routing across
 *    each side's gvisor netstack) for traffic to flow, and that's
 *    a separate question this PoC isn't trying to answer.
 *  - Higher-level wiring (`HostModeBackend` would need its
 *    single-instance check lifted; UI / persistence assume one
 *    active host tunnel).  Those changes are out of scope until
 *    we confirm the foundation works.
 *
 * If this test panics or any assertion fails, it pins the failure
 * to either the cgo //export layer or wireguard-go itself rather
 * than to Kotlin glue — invaluable for the architecture decision
 * about whether multi-host support is feasible.
 */
@RunWith(AndroidJUnit4::class)
class MultiHostBridgeCoexistenceTest {

    @Volatile private var handleA: Int = 0
    @Volatile private var handleB: Int = 0

    @After fun tearDown() {
        // Don't close — close+reopen has had history of cgo
        // panics across some runtimes (see
        // `HostModeBackendInstrumentedTest.startStopStartCycleDoesNotCrash`
        // for the documented mitigation).  Letting the process
        // exit at instrumentation teardown is the safe path.
    }

    @Test
    fun twoHostBridgesCoexistInOneProcess() {
        val (privA, pubA) = newKeyPair()
        val (privB, pubB) = newKeyPair()
        // Stub peer keypairs — we never bring up these peers; we just
        // want valid base64 entries in each host's UAPI peer table
        // to confirm the configure round-trips per-instance state.
        val (_, peerOfA) = newKeyPair()
        val (_, peerOfB) = newKeyPair()

        val portA = 51000 + (SecureRandom().nextInt(250))
        var portB = 51250 + (SecureRandom().nextInt(250))
        if (portA == portB) portB += 1  // defensive — pickers are
                                        // independent random draws.

        // -- Host A on 10.99.0.1, port = portA ----------------------
        handleA = WgBridgeNative.nativeNew(
            localAddr = "10.99.0.1", mtu = 1420, listenPort = portA,
        )
        assertTrue("host A nativeNew=$handleA", handleA > 0)
        val uapiA = buildString {
            append("private_key=").append(privA).append('\n')
            append("listen_port=").append(portA).append('\n')
            append("replace_peers=true\n")
            append("public_key=").append(peerOfA).append('\n')
            append("allowed_ip=10.99.0.2/32\n")
        }
        assertEquals("configure A", 0,
            WgBridgeNative.nativeConfigureUAPI(handleA, uapiA))

        // -- Host B on 10.100.0.1, port = portB ---------------------
        handleB = WgBridgeNative.nativeNew(
            localAddr = "10.100.0.1", mtu = 1420, listenPort = portB,
        )
        assertTrue("host B nativeNew=$handleB", handleB > 0)
        assertNotEquals("handles must be distinct", handleA, handleB)
        val uapiB = buildString {
            append("private_key=").append(privB).append('\n')
            append("listen_port=").append(portB).append('\n')
            append("replace_peers=true\n")
            append("public_key=").append(peerOfB).append('\n')
            append("allowed_ip=10.100.0.2/32\n")
        }
        assertEquals("configure B", 0,
            WgBridgeNative.nativeConfigureUAPI(handleB, uapiB))

        // -- Snapshots must reflect independent peer tables ---------
        val snapA = WgBridgeNative.nativeSnapshotUAPI(handleA)
            ?: org.junit.Assert.fail("host A snapshot null") as String
        val snapB = WgBridgeNative.nativeSnapshotUAPI(handleB)
            ?: org.junit.Assert.fail("host B snapshot null") as String

        // A's snapshot must contain A's peer (and A's listen port);
        // it must NOT contain B's peer.  `newKeyPair()` already
        // returns the public key in lowercase hex, which is the same
        // format `wireguard-go`'s UAPI dump emits, so a direct
        // substring check is enough.
        assertTrue("A snapshot should mention peer-of-A ($peerOfA):\n$snapA",
            snapA.contains(peerOfA, ignoreCase = true))
        assertTrue("A snapshot should mention listen_port=$portA:\n$snapA",
            snapA.contains("listen_port=$portA"))
        assertTrue("A snapshot must NOT contain peer-of-B ($peerOfB):\n$snapA",
            !snapA.contains(peerOfB, ignoreCase = true))

        assertTrue("B snapshot should mention peer-of-B ($peerOfB):\n$snapB",
            snapB.contains(peerOfB, ignoreCase = true))
        assertTrue("B snapshot should mention listen_port=$portB:\n$snapB",
            snapB.contains("listen_port=$portB"))
        assertTrue("B snapshot must NOT contain peer-of-A ($peerOfA):\n$snapB",
            !snapB.contains(peerOfA, ignoreCase = true))

        android.util.Log.i("MultiHostBridge",
            "two host bridges coexist: handleA=$handleA " +
                "port=$portA; handleB=$handleB port=$portB")
    }

    // ─── helpers (mirrored from HostNativeSelfLoopTest) ───────────

    private fun newKeyPair(): Pair<String, String> {
        val priv = ByteArray(32).apply { SecureRandom().nextBytes(this) }
        priv[0] = (priv[0].toInt() and 248).toByte()
        priv[31] = ((priv[31].toInt() and 127) or 64).toByte()
        val kf = java.security.KeyFactory.getInstance("XDH")
        val privSpec = java.security.spec.PKCS8EncodedKeySpec(
            wrapPrivateAsPkcs8(priv))
        val privKey = kf.generatePrivate(privSpec)
        val ka = javax.crypto.KeyAgreement.getInstance("XDH")
        ka.init(privKey)
        val base = ByteArray(32); base[0] = 9
        val basePub = kf.generatePublic(
            java.security.spec.X509EncodedKeySpec(wrapPublicAsX509(base)))
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
    private fun hex(b: ByteArray): String = buildString(b.size * 2) {
        for (x in b) append("%02x".format(x.toInt() and 0xff))
    }
}
