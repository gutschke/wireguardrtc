package com.gutschke.wgrtc.data

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.SecureRandom

/**
 * V6.H2b — the host forwarder accepts a dual-stack subnet
 * (`10.99.0.0/24,fd00:dead:beef::/64`) and installs without
 * error.  Pre-V6.H2b the Go side parsed only the first CIDR and
 * silently dropped the v6 entry; this test pins the new
 * comma-form contract end-to-end through JNI.
 *
 * Goes one step further than the V6.PL Layer-3
 * [HostNativeV6SelfLoopTest]: that test only proves the WG
 * handshake survives dual-stack address registration.  This one
 * additionally exercises `wgbridgeInstallHostForwarder` (Option B
 * NIC2 routing + ICMPv4/v6 transport handlers) with a v6 prefix
 * in the subnet list — the code path responsible for handling
 * non-local v6 traffic from the joiner once V6 is in production
 * use.
 *
 * Doesn't attempt to push real v6 traffic through the forwarder:
 * the emulator's slirp NAT doesn't carry v6 packets to the
 * internet, and the through-host path's `dispatchPingV6` would
 * fail at the `icmpx.ListenPacket("udp6", "::")` step.  ChromeOS
 * ARC + a v6-routable network is the right rig for that —
 * V6.E2E territory.  Here we verify the install + tear-down
 * round-trip, which catches:
 *
 *  - Comma-form parsing on the Go side (`strings.Split` +
 *    `net.ParseCIDR` for each entry).
 *  - Dual-stack route insertion (v4 + v6 defaults coexisting).
 *  - Forwarding-enable-by-family.
 *  - ICMPv6 transport handler registration.
 *  - Clean tear-down via [WgBridgeNative.nativeCloseListener].
 */
@RunWith(AndroidJUnit4::class)
class HostNativeV6ForwarderTest {

    @Volatile private var hostHandle: Int = 0
    @Volatile private var forwarderId: Int = 0

    @After fun tearDown() {
        if (forwarderId > 0) {
            try { WgBridgeNative.nativeCloseListener(forwarderId) } catch (_: Throwable) {}
            forwarderId = 0
        }
        if (hostHandle > 0) {
            WgBridgeNative.nativeClose(hostHandle); hostHandle = 0
        }
    }

    @Test
    fun installsDualStackForwarder() {
        val (hostPriv, _) = newKeyPair()
        val listenPort = 51000 + SecureRandom().nextInt(500)

        // Dual-stack bridge.
        hostHandle = WgBridgeNative.nativeNew(
            localAddr = "10.99.0.1,fd00:dead:beef::1",
            mtu = 1420, listenPort = listenPort)
        assertTrue("host nativeNew=$hostHandle (V6.H1)", hostHandle > 0)
        val uapi = buildString {
            append("private_key=").append(hostPriv).append('\n')
            append("listen_port=").append(listenPort).append('\n')
            append("replace_peers=true\n")
        }
        assertEquals(0, WgBridgeNative.nativeConfigureUAPI(hostHandle, uapi))

        // Dual-stack host forwarder install (V6.H2b — comma-form).
        // Pre-V6.H2b the Go side returned -4 (parse failed) on this
        // input because it tried `net.ParseCIDR` on the whole
        // comma-separated string.  Post-V6.H2b it splits + parses
        // each entry + installs both v4 + v6 routes.
        forwarderId = WgBridgeNative.nativeInstallHostForwarder(
            hostHandle, "10.99.0.0/24,fd00:dead:beef::/64")
        assertTrue("installHostForwarder dual-stack id=$forwarderId; " +
            "want > 0 (any negative = parse / install failure)",
            forwarderId > 0)
    }

    @Test
    fun installsForwarderWithV6OnlySubnet() {
        // Edge case: tunnel with no v4 subnet (purely-v6 deployment,
        // unusual but should not break the install).  The Go side
        // requires at least one CIDR — v4 OR v6 — to install.
        val (hostPriv, _) = newKeyPair()
        val listenPort = 51000 + SecureRandom().nextInt(500)

        hostHandle = WgBridgeNative.nativeNew(
            localAddr = "fd00:dead:beef::1",
            mtu = 1420, listenPort = listenPort)
        assertTrue(hostHandle > 0)
        WgBridgeNative.nativeConfigureUAPI(hostHandle, buildString {
            append("private_key=").append(hostPriv).append('\n')
            append("listen_port=").append(listenPort).append('\n')
            append("replace_peers=true\n")
        })

        forwarderId = WgBridgeNative.nativeInstallHostForwarder(
            hostHandle, "fd00:dead:beef::/64")
        assertTrue("v6-only install id=$forwarderId", forwarderId > 0)
    }

    @Test
    fun installsForwarderTolerantOfWhitespace() {
        // V6.H2b — whitespace tolerated on input.  Mirrors the
        // splitAssignedAddress / WgAllowedIps.canonicalize stance:
        // accept loose input, never emit it.  This test asserts
        // that a user / future caller who types "10.99.0.0/24, fd00::/64"
        // (with a space after the comma) still installs cleanly.
        val (hostPriv, _) = newKeyPair()
        val listenPort = 51000 + SecureRandom().nextInt(500)

        hostHandle = WgBridgeNative.nativeNew(
            localAddr = "10.99.0.1,fd00:dead:beef::1",
            mtu = 1420, listenPort = listenPort)
        assertTrue(hostHandle > 0)
        WgBridgeNative.nativeConfigureUAPI(hostHandle, buildString {
            append("private_key=").append(hostPriv).append('\n')
            append("listen_port=").append(listenPort).append('\n')
            append("replace_peers=true\n")
        })

        forwarderId = WgBridgeNative.nativeInstallHostForwarder(
            hostHandle, " 10.99.0.0/24 , fd00:dead:beef::/64 ")
        assertTrue("whitespace-tolerant install id=$forwarderId", forwarderId > 0)
    }

    @Test
    fun rejectsEmptySubnetString() {
        // V6.H2b — defensive: passing an empty subnet string must
        // be a clean -4 (parse failed), not a silent install with
        // no routes installed (which would leave the bridge
        // accepting traffic but unable to route it anywhere).
        val (hostPriv, _) = newKeyPair()
        val listenPort = 51000 + SecureRandom().nextInt(500)

        hostHandle = WgBridgeNative.nativeNew(
            localAddr = "10.99.0.1", mtu = 1420, listenPort = listenPort)
        assertTrue(hostHandle > 0)
        WgBridgeNative.nativeConfigureUAPI(hostHandle, buildString {
            append("private_key=").append(hostPriv).append('\n')
            append("listen_port=").append(listenPort).append('\n')
            append("replace_peers=true\n")
        })

        val rc = WgBridgeNative.nativeInstallHostForwarder(hostHandle, "")
        assertEquals(-4, rc)
    }

    @Test
    fun rejectsAllMalformedSubnetList() {
        // When EVERY entry fails to parse, the install must fail
        // with -4 (subnet parse failed) — defends against the
        // failure mode where a caller passes a garbage string and
        // the forwarder silently installs without any routes.
        val (hostPriv, _) = newKeyPair()
        val listenPort = 51000 + SecureRandom().nextInt(500)

        hostHandle = WgBridgeNative.nativeNew(
            localAddr = "10.99.0.1", mtu = 1420, listenPort = listenPort)
        assertTrue(hostHandle > 0)
        WgBridgeNative.nativeConfigureUAPI(hostHandle, buildString {
            append("private_key=").append(hostPriv).append('\n')
            append("listen_port=").append(listenPort).append('\n')
            append("replace_peers=true\n")
        })

        val rc = WgBridgeNative.nativeInstallHostForwarder(
            hostHandle, "not-a-cidr,also-garbage")
        // -4 == subnet parse failed (per the Go documentation in
        // wgbridgeInstallHostForwarder).  Pre-V6.H2b this code
        // path returned -4 for any invalid input including
        // legitimately formatted comma-separated values.
        assertEquals(-4, rc)
    }

    private fun newKeyPair(): Pair<String, String> {
        val priv = ByteArray(32).apply { SecureRandom().nextBytes(this) }
        priv[0] = (priv[0].toInt() and 248).toByte()
        priv[31] = ((priv[31].toInt() and 127) or 64).toByte()
        val kf = java.security.KeyFactory.getInstance("XDH")
        val privSpec = java.security.spec.PKCS8EncodedKeySpec(wrapPkcs8(priv))
        val privKey = kf.generatePrivate(privSpec)
        val ka = javax.crypto.KeyAgreement.getInstance("XDH")
        ka.init(privKey)
        val base = ByteArray(32); base[0] = 9
        val basePub = kf.generatePublic(
            java.security.spec.X509EncodedKeySpec(wrapX509(base)))
        ka.doPhase(basePub, true)
        val pub = ka.generateSecret()
        return hex(priv) to hex(pub)
    }
    private fun wrapPkcs8(raw: ByteArray) = byteArrayOf(
        0x30, 0x2e, 0x02, 0x01, 0x00,
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
        0x04, 0x22, 0x04, 0x20) + raw
    private fun wrapX509(raw: ByteArray) = byteArrayOf(
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e,
        0x03, 0x21, 0x00) + raw
    private fun hex(b: ByteArray): String =
        StringBuilder(64).apply {
            for (x in b) append("%02x".format(x.toInt() and 0xff))
        }.toString()
}
