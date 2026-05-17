package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class BridgeGroupingTest {

    private fun t(
        id: String,
        name: String,
        source: Tunnel.Source = Tunnel.Source.MANUAL,
        groupId: String? = null,
    ) = Tunnel(
        id = id,
        name = name,
        configText = "[Interface]\n",
        source = source,
        groupId = groupId,
    )

    @Test fun `empty input yields empty output`() {
        assertTrue(groupTunnels(emptyList()).isEmpty())
    }

    @Test fun `tunnels with no groupId render as singles`() {
        val a = t("a", "alpha")
        val b = t("b", "beta")
        val out = groupTunnels(listOf(a, b))
        assertEquals(2, out.size)
        assertEquals(TunnelListEntry.Single(a), out[0])
        assertEquals(TunnelListEntry.Single(b), out[1])
    }

    @Test fun `two-member group collapses to a Bridge`() {
        val a = t("a", "home", source = Tunnel.Source.HOST_MODE, groupId = "g1")
        val b = t("b", "work", groupId = "g1")
        val out = groupTunnels(listOf(a, b))
        assertEquals(1, out.size)
        val bridge = out[0] as TunnelListEntry.Bridge
        assertEquals("g1", bridge.groupId)
        // Host-mode wins the "first" slot.
        assertEquals("a", bridge.first.id)
        assertEquals("b", bridge.second.id)
        assertEquals("home ↔ work", bridge.displayName)
    }

    @Test fun `Bridge ordering puts host before joiner regardless of input order`() {
        val joiner = t("j", "work", groupId = "g")
        val host = t("h", "home", source = Tunnel.Source.HOST_MODE, groupId = "g")
        val out = groupTunnels(listOf(joiner, host))
        val bridge = out[0] as TunnelListEntry.Bridge
        assertEquals("h", bridge.first.id, "host must be first")
        assertEquals("j", bridge.second.id, "joiner must be second")
    }

    @Test fun `two non-host members preserve input order`() {
        // Edge case: both halves are joiner-source.  Not really
        // useful as a relay, but the grouping function shouldn't
        // crash and should keep order stable.
        val a = t("a", "alpha", groupId = "g")
        val b = t("b", "beta", groupId = "g")
        val out = groupTunnels(listOf(a, b))
        val bridge = out[0] as TunnelListEntry.Bridge
        assertEquals("a", bridge.first.id)
        assertEquals("b", bridge.second.id)
    }

    @Test fun `group-of-one renders as Single`() {
        // Sibling deleted; the surviving half should appear as a
        // normal row, NOT a collapsed Bridge that displays a
        // single name in the "X ↔ ?" slot.
        val orphan = t("a", "orphan", groupId = "g")
        val out = groupTunnels(listOf(orphan))
        assertEquals(1, out.size)
        assertTrue(out[0] is TunnelListEntry.Single)
    }

    @Test fun `group-of-three renders every member as Single`() {
        // Misconfiguration state we should never reach in production
        // but the function must not silently drop tunnels.
        val a = t("a", "alpha", groupId = "g")
        val b = t("b", "beta", groupId = "g")
        val c = t("c", "gamma", groupId = "g")
        val out = groupTunnels(listOf(a, b, c))
        assertEquals(3, out.size)
        assertTrue(out.all { it is TunnelListEntry.Single })
    }

    @Test fun `mixed list keeps Bridge in the first member's slot`() {
        // Order property: a Bridge takes the slot of the FIRST member
        // we encountered; the second member is consumed in place.
        // Tunnels with no groupId interleave in their original
        // positions.
        val s1 = t("s1", "stand-alone-1")
        val a = t("a", "home", source = Tunnel.Source.HOST_MODE, groupId = "g")
        val s2 = t("s2", "stand-alone-2")
        val b = t("b", "work", groupId = "g")
        val s3 = t("s3", "stand-alone-3")
        val out = groupTunnels(listOf(s1, a, s2, b, s3))
        assertEquals(4, out.size)
        assertEquals(TunnelListEntry.Single(s1), out[0])
        assertTrue(out[1] is TunnelListEntry.Bridge, "bridge takes slot 1 (first member's slot)")
        assertEquals(TunnelListEntry.Single(s2), out[2])
        assertEquals(TunnelListEntry.Single(s3), out[3])
    }

    @Test fun `null groupId never matches another null`() {
        // Sanity: two tunnels with null groupId are NOT paired —
        // null means "no Bridge intent".
        val a = t("a", "alpha")
        val b = t("b", "beta")
        val out = groupTunnels(listOf(a, b))
        assertEquals(2, out.size)
        assertTrue(out.all { it is TunnelListEntry.Single })
    }

    @Test fun `Bridge displayName uses Unicode bidirectional arrow`() {
        val a = t("a", "north", groupId = "g")
        val b = t("b", "south", groupId = "g")
        val bridge = groupTunnels(listOf(a, b))[0] as TunnelListEntry.Bridge
        // U+2194 LEFT RIGHT ARROW — the design's chosen separator
        // for paired Bridges.  Pinned because the same character
        // appears in the long-press menu's "Rename to A ↔ B" copy
        // (§11.8b).
        assertTrue(bridge.displayName.contains("↔"))
    }
}
