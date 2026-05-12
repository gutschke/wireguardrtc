package com.gutschke.wgrtc.ui

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

/**
 * **target-inference helpers.**
 *
 * Pure-string helpers for picking a default ping target from a
 * wg-quick config. Kept here (a test in `app/src/test/`) rather
 * than as instrumented tests because there's no Android API
 * involved + the matrix is small enough that a JVM unit run is
 * the right tool.
 */
class DiagnosticsTargetsTest {

    @Test fun inferHostAddressFromAllowedIpsSlash32() {
        val cfg = """
            [Interface]
            PrivateKey = abc
            Address = 10.99.0.2/24
            [Peer]
            PublicKey = xyz
            AllowedIPs = 10.99.0.1/32
        """.trimIndent()
        assertEquals("10.99.0.1", DiagnosticsTargets.inferHostAddress(cfg))
    }

    @Test fun inferHostAddressFromAllowedIpsSlash24() {
        val cfg = """
            [Interface]
            Address = 10.99.0.2/24
            [Peer]
            PublicKey = xyz
            AllowedIPs = 10.99.0.0/24
        """.trimIndent()
        // The first usable host of 10.99.0.0/24 is 10.99.0.1.
        assertEquals("10.99.0.1", DiagnosticsTargets.inferHostAddress(cfg))
    }

    @Test fun inferHostAddressFromAllowedIpsFullTunnelFallsBackToInterface() {
        // AllowedIPs = 0.0.0.0/0 isn't actually useful as a host
        // target ("first host of 0.0.0.0/0" = 0.0.0.1, garbage),
        // but the parser still returns it. This is documented
        // behaviour — the user's expected to edit the textfield
        // away from a clearly-wrong default.
        val cfg = """
            [Interface]
            Address = 10.99.0.2/24
            [Peer]
            PublicKey = xyz
            AllowedIPs = 0.0.0.0/0
        """.trimIndent()
        assertEquals("0.0.0.1", DiagnosticsTargets.inferHostAddress(cfg))
    }

    @Test fun inferHostAddressFromInterfaceWhenNoAllowedIps() {
        val cfg = """
            [Interface]
            Address = 10.99.0.5/24
            [Peer]
            PublicKey = xyz
        """.trimIndent()
        // No AllowedIPs → fall back to "first three octets of
        // interface address + .1".
        assertEquals("10.99.0.1", DiagnosticsTargets.inferHostAddress(cfg))
    }

    @Test fun inferHostAddressNullWhenAddressMissing() {
        val cfg = """
            [Interface]
            PrivateKey = abc
            [Peer]
            PublicKey = xyz
        """.trimIndent()
        assertNull(DiagnosticsTargets.inferHostAddress(cfg))
    }

    @Test fun firstIpOfSubnetSlash24() {
        assertEquals("10.0.0.1", DiagnosticsTargets.firstIpOfSubnet("10.0.0.0/24"))
        assertEquals("192.168.42.1",
            DiagnosticsTargets.firstIpOfSubnet("192.168.42.0/24"))
    }

    @Test fun firstIpOfSubnetSlash32() {
        // A /32 is a single address — there's no "first usable
        // host" in the conventional sense, so we just return the
        // address as-is.
        assertEquals("10.99.0.1",
            DiagnosticsTargets.firstIpOfSubnet("10.99.0.1/32"))
    }

    @Test fun firstIpOfSubnetNullOnBadInput() {
        assertNull(DiagnosticsTargets.firstIpOfSubnet(""))
        assertNull(DiagnosticsTargets.firstIpOfSubnet("not-an-ip"))
        assertNull(DiagnosticsTargets.firstIpOfSubnet("10.0.0.0/99"))
        assertNull(DiagnosticsTargets.firstIpOfSubnet("999.999.999.999/24"))
    }

    @Test fun firstIpOfSubnetSlash16() {
        assertEquals("10.0.0.1", DiagnosticsTargets.firstIpOfSubnet("10.0.0.0/16"))
        // First usable host of 172.16.5.42/16 = 172.16.0.1.
        assertEquals("172.16.0.1", DiagnosticsTargets.firstIpOfSubnet("172.16.5.42/16"))
    }
}
