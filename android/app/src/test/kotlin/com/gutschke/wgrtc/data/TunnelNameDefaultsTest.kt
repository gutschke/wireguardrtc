package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * Pins the §11.9 unique-name default helper against the failure
 * modes the round-2 critic of `defaultHostName` called out:
 *
 *  - rewind after deletes: returns the lowest free suffix, not
 *    `size + 1`;
 *  - cross-prefix independence: `Host N` doesn't push `tunnel-N`
 *    and vice versa;
 *  - case-insensitive collisions: `HOST 1` (uppercase user input)
 *    pushes `Host 2`;
 *  - empty input: returns `<prefix>1`.
 */
class TunnelNameDefaultsTest {

    @Test fun `empty input returns N=1`() {
        assertEquals("tunnel-1", nextAvailableTunnelName(emptyList(), "tunnel"))
        assertEquals("Host 1", nextAvailableTunnelName(emptyList(), "Host", " "))
    }

    @Test fun `picks the lowest free suffix`() {
        assertEquals(
            "tunnel-1",
            nextAvailableTunnelName(listOf("tunnel-2", "tunnel-3"), "tunnel"),
        )
        assertEquals(
            "tunnel-2",
            nextAvailableTunnelName(listOf("tunnel-1", "tunnel-3"), "tunnel"),
        )
        assertEquals(
            "tunnel-4",
            nextAvailableTunnelName(
                listOf("tunnel-1", "tunnel-2", "tunnel-3"), "tunnel"),
        )
    }

    @Test fun `delete-then-create reuses freed suffix`() {
        // The original size+1 bug: with two tunnels {tunnel-1, tunnel-3}
        // (tunnel-2 was deleted), size+1 says tunnel-3 — collision.
        // Fixed: returns tunnel-2.
        assertEquals(
            "tunnel-2",
            nextAvailableTunnelName(listOf("tunnel-1", "tunnel-3"), "tunnel"),
        )
    }

    @Test fun `cross-prefix independence`() {
        // Having Host 1 / Host 2 in the set shouldn't push tunnel-1.
        assertEquals(
            "tunnel-1",
            nextAvailableTunnelName(listOf("Host 1", "Host 2"), "tunnel"),
        )
        // Symmetrically, tunnel-1 / tunnel-2 shouldn't push Host 1.
        assertEquals(
            "Host 1",
            nextAvailableTunnelName(listOf("tunnel-1", "tunnel-2"), "Host", " "),
        )
    }

    @Test fun `case-insensitive collision pushes to next free`() {
        // HOST 1 from a user with caps-lock should still block Host 1.
        assertEquals(
            "Host 2",
            nextAvailableTunnelName(listOf("HOST 1"), "Host", " "),
        )
        // host 1 (lowercase user input) blocks too.
        assertEquals(
            "Host 2",
            nextAvailableTunnelName(listOf("host 1"), "Host", " "),
        )
    }

    @Test fun `mixed-case existing pool resolves correctly`() {
        // Real user data is rarely uniform-case; the search must
        // succeed regardless of how the user wrote the existing
        // entries.
        val pool = listOf("TUNNEL-1", "tunnel-2", "Tunnel-4")
        assertEquals("tunnel-3", nextAvailableTunnelName(pool, "tunnel"))
    }

    @Test fun `unrelated names in the pool are ignored`() {
        // The pool may contain user-named tunnels ("Home", "Work")
        // that don't match either prefix.  They must not influence
        // the scan.
        assertEquals(
            "Host 1",
            nextAvailableTunnelName(listOf("Home", "Work", "tunnel-1"), "Host", " "),
        )
    }

    @Test fun `separator is configurable`() {
        // "Host 1" uses a space; "tunnel-1" uses a hyphen.  Both
        // paths must compose suffix the same way.
        assertEquals(
            "Host_1",
            nextAvailableTunnelName(listOf("Host 1"), "Host", "_"),
        )
    }

    @Test fun `large pool still terminates`() {
        // Pragmatic: 10k pre-existing matches resolve in
        // sub-millisecond.  This test would diverge if anyone
        // ever swapped the implementation for a non-terminating
        // search (e.g. recursive without a base case).
        val pool = (1..10_000).map { "tunnel-$it" }
        assertEquals("tunnel-10001", nextAvailableTunnelName(pool, "tunnel"))
    }
}
