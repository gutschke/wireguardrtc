package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class HostPortDefaultsTest {

    @Test fun `empty pool returns 51820`() {
        // First-ever host tunnel: prefer the WG canonical port.
        assertEquals(51820, nextAvailableHostListenPort(emptyList()))
    }

    @Test fun `51820 taken walks to 51821`() {
        assertEquals(51821, nextAvailableHostListenPort(listOf(51820)))
    }

    @Test fun `walks over consecutive taken ports`() {
        assertEquals(
            51823,
            nextAvailableHostListenPort(listOf(51820, 51821, 51822)),
        )
    }

    @Test fun `gaps in the taken set are filled lowest-first`() {
        // 51820 free, 51821 taken: scan starts at preferred (51820)
        // and returns it.  The "lowest-first" property kicks in only
        // when the preferred port itself is taken.
        assertEquals(
            51820,
            nextAvailableHostListenPort(listOf(51821, 51823)),
        )
    }

    @Test fun `preferred override picks a non-default starting point`() {
        // Some users prefer 51900 for a "this is wgrtc, not generic
        // WG" convention.  The helper honours any unprivileged-port
        // preferred value.
        assertEquals(51900, nextAvailableHostListenPort(emptyList(), preferred = 51900))
        assertEquals(51901, nextAvailableHostListenPort(listOf(51900), preferred = 51900))
    }

    @Test fun `preferred must be unprivileged`() {
        // Port 80 / 443 / etc. would need CAP_NET_BIND_SERVICE on
        // Linux and is forbidden for an unprivileged Android UID.
        assertThrows(IllegalArgumentException::class.java) {
            nextAvailableHostListenPort(emptyList(), preferred = 80)
        }
        assertThrows(IllegalArgumentException::class.java) {
            nextAvailableHostListenPort(emptyList(), preferred = 1023)
        }
        // Boundary: 1024 is the lowest unprivileged port.
        assertEquals(1024, nextAvailableHostListenPort(emptyList(), preferred = 1024))
    }

    @Test fun `unrelated ports in the pool are skipped past`() {
        // The pool can contain ephemeral / random listen ports from
        // tunnels the user typed by hand.  As long as preferred and
        // its neighbours are free, those wider values don't matter.
        assertEquals(
            51820,
            nextAvailableHostListenPort(listOf(38291, 49001, 62015)),
        )
    }

    @Test fun `running out of ports throws`() {
        // The check() at the top of the scan kicks in when there's
        // genuinely no free port left.  In practice this can only
        // happen if a malicious / buggy caller passes the full
        // upper range pre-bound; pin the error path anyway so a
        // future implementation change doesn't silently return -1
        // or 0.
        val takenAbove = (51820..65535).toList()
        assertThrows(IllegalStateException::class.java) {
            nextAvailableHostListenPort(takenAbove)
        }
    }

    @Test fun `DEFAULT_HOST_LISTEN_PORT is 51820`() {
        // Pinned so downstream callers (HostModeSetupScreen) don't
        // silently switch off WG's canonical port without an
        // accompanying review.
        assertEquals(51820, DEFAULT_HOST_LISTEN_PORT)
    }

    @Test fun `parseListenPortFromConfig extracts the value`() {
        val cfg = """
            [Interface]
            PrivateKey = abc
            Address = 10.99.0.1/24
            ListenPort = 51900
        """.trimIndent()
        assertEquals(51900, parseListenPortFromConfig(cfg))
    }

    @Test fun `parseListenPortFromConfig returns null when absent`() {
        val cfg = """
            [Interface]
            PrivateKey = abc
            Address = 10.99.0.1/24
        """.trimIndent()
        assertEquals(null, parseListenPortFromConfig(cfg))
    }

    @Test fun `parseListenPortFromConfig returns null on garbage`() {
        // "not-a-number" should not throw — null lets the caller
        // fall back to the default rather than crashing.
        val cfg = """
            [Interface]
            ListenPort = not-a-number
        """.trimIndent()
        assertEquals(null, parseListenPortFromConfig(cfg))
    }

    @Test fun `joiner-mode pool is the caller's responsibility to filter out`() {
        // The helper itself doesn't filter by mode — it operates on
        // a plain `Collection<Int>`.  The intentional design (per
        // §11.9 + the round-2 critic's missing-test catch) is that
        // [WgrtcViewModel.defaultHostListenPort] is the only call
        // site that filters HOST_MODE-only.  Pin the helper's
        // mode-agnostic contract here so a future refactor that
        // pushes filtering into this layer doesn't slip past.
        // (i.e. if the helper became filter-aware we'd want a
        // signature change, caught by this test breaking.)
        val mixed = listOf(51820)  // could be host OR joiner — helper doesn't know.
        assertEquals(51821, nextAvailableHostListenPort(mixed))
    }

    // ─── findCollidingHostTunnel — §11.9c inline check ─────────

    private fun hostTunnel(id: String, name: String, port: Int): Tunnel = Tunnel(
        id = id,
        name = name,
        configText = "[Interface]\nPrivateKey = abc\n" +
            "Address = 10.99.0.1/24\nListenPort = $port\n",
        source = Tunnel.Source.HOST_MODE,
    )

    @Test fun `findColliding returns null when no host tunnels`() {
        assertEquals(
            null,
            findCollidingHostTunnel(emptyList(), emptySet(), 51820),
        )
    }

    @Test fun `findColliding returns the active host tunnel's name`() {
        val t1 = hostTunnel("t1", "home", 51820)
        assertEquals(
            "home",
            findCollidingHostTunnel(listOf(t1), setOf("t1"), 51820),
        )
    }

    @Test fun `findColliding ignores paused host tunnels (mirrors backend)`() {
        // CRITICAL §11.9c invariant: HostModeBackend.start permits
        // binding a port that another HOST_MODE tunnel "owns" if
        // that tunnel is currently paused (its slot.listenPort
        // sits at 0 per the pause UAPI).  The inline check must
        // match — otherwise the UI grays out Save on a port the
        // backend would happily accept.  Critic round-2 caught
        // this exact divergence.
        val active = hostTunnel("t1", "home", 51820)
        val paused = hostTunnel("t2", "work", 51821)
        // Only t1 is in activeHostTunnelIds; t2 is paused.
        assertEquals(
            "home",
            findCollidingHostTunnel(
                listOf(active, paused), setOf("t1"), 51820),
        )
        // Typing 51821 finds nothing — the paused tunnel doesn't
        // count as a collision.
        assertEquals(
            null,
            findCollidingHostTunnel(
                listOf(active, paused), setOf("t1"), 51821),
        )
    }

    @Test fun `findColliding skips joiner-mode tunnels even when active`() {
        // Joiners don't bind a fixed source port; their persisted
        // ListenPort (if any) is meaningless to the host-side
        // collision check.
        val joiner = Tunnel(
            id = "j1",
            name = "remote",
            configText = "[Interface]\nListenPort = 51820\n",
            source = Tunnel.Source.MANUAL,
        )
        assertEquals(
            null,
            findCollidingHostTunnel(listOf(joiner), setOf("j1"), 51820),
        )
    }

    @Test fun `findColliding skips host tunnels with missing ListenPort`() {
        // Hand-edited configs that stripped the field are invisible
        // to the inline check (the runtime PortCollisionException
        // remains the backstop).  Pin so a future refactor doesn't
        // start silently throwing on null.
        val cfg = Tunnel(
            id = "t1",
            name = "stripped",
            configText = "[Interface]\nPrivateKey = abc\n",  // no ListenPort
            source = Tunnel.Source.HOST_MODE,
        )
        assertEquals(
            null,
            findCollidingHostTunnel(listOf(cfg), setOf("t1"), 51820),
        )
    }

    @Test fun `findColliding returns null for a port nobody uses`() {
        val t1 = hostTunnel("t1", "home", 51820)
        val t2 = hostTunnel("t2", "work", 51821)
        assertEquals(
            null,
            findCollidingHostTunnel(
                listOf(t1, t2), setOf("t1", "t2"), 51822),
        )
    }

    @Test fun `findColliding returns first match when multiple active tunnels share the port`() {
        // Shouldn't happen at the backend level (the backend's
        // collision check would have refused the second to bind),
        // but pin the deterministic-iteration property anyway.
        val t1 = hostTunnel("t1", "home", 51820)
        val t2 = hostTunnel("t2", "work", 51820)
        assertEquals(
            "home",
            findCollidingHostTunnel(
                listOf(t1, t2), setOf("t1", "t2"), 51820),
        )
    }

    @Test fun `realistic two-host pool returns 51821 then 51822`() {
        // End-to-end style smoke: simulate creating two host
        // tunnels back-to-back; the second should see 51821.
        val first = nextAvailableHostListenPort(emptyList())
        assertEquals(51820, first)
        val second = nextAvailableHostListenPort(listOf(first))
        assertEquals(51821, second)
        val third = nextAvailableHostListenPort(listOf(first, second))
        assertEquals(51822, third)
        // Free the second slot (delete tunnel 51821) — third pick
        // rewinds.
        assertTrue(nextAvailableHostListenPort(listOf(first, 51822)) == 51821)
    }
}
