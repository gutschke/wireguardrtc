package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * Pin the behavior of [effectiveRejectIfInside]: catchall ranges
 * (`0.0.0.0/0`, `::/0`) must be filtered out of the OFFER decoder's
 * deadlock guard so the listener cache populates for full-tunnel
 * ENROLLs. A regression here breaks the "phone receives broker
 * OFFERs" path entirely — caught a serious silent failure during the
 * 2026-05-08 debug session.
 */
class EffectiveRejectIfInsideTest {

    @Test
    fun `catchall v4 alone yields empty list`() {
        val cfg = """
            [Peer]
            AllowedIPs = 0.0.0.0/0
        """.trimIndent()
        assertEquals(emptyList<String>(), effectiveRejectIfInside(cfg))
    }

    @Test
    fun `catchall v4 plus catchall v6 yields empty list`() {
        val cfg = """
            [Peer]
            AllowedIPs = 0.0.0.0/0, ::/0
        """.trimIndent()
        assertEquals(emptyList<String>(), effectiveRejectIfInside(cfg))
    }

    @Test
    fun `narrow v4 range is preserved`() {
        val cfg = """
            [Peer]
            AllowedIPs = 10.0.0.0/8
        """.trimIndent()
        assertEquals(listOf("10.0.0.0/8"), effectiveRejectIfInside(cfg))
    }

    @Test
    fun `narrow ranges preserved when mixed with catchall`() {
        val cfg = """
            [Peer]
            AllowedIPs = 0.0.0.0/0, 192.168.1.0/24, ::/0, fd00::/8
        """.trimIndent()
        // Catchalls dropped, narrower ranges retained in order.
        assertEquals(
            listOf("192.168.1.0/24", "fd00::/8"),
            effectiveRejectIfInside(cfg)
        )
    }

    @Test
    fun `bare host IP is normalized then preserved`() {
        // parseAllowedIps normalizes bare IPs to /32 (v4) / /128 (v6).
        val cfg = """
            [Peer]
            AllowedIPs = 10.20.30.40
        """.trimIndent()
        assertEquals(listOf("10.20.30.40/32"), effectiveRejectIfInside(cfg))
    }

    @Test
    fun `no AllowedIPs line yields empty list`() {
        val cfg = """
            [Interface]
            PrivateKey = AAA
        """.trimIndent()
        assertEquals(emptyList<String>(), effectiveRejectIfInside(cfg))
    }

    @Test
    fun `multiple AllowedIPs lines are unioned then catchall-filtered`() {
        // wg-quick accepts multiple AllowedIPs lines; parseAllowedIps
        // unions them.
        val cfg = """
            [Peer]
            AllowedIPs = 0.0.0.0/0
            AllowedIPs = 172.16.0.0/12
        """.trimIndent()
        assertEquals(listOf("172.16.0.0/12"), effectiveRejectIfInside(cfg))
    }
}
