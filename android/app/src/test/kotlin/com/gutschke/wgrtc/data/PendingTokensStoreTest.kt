package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path

/**
 * Unit tests for [PendingTokensStore], the phone-side ephemeral
 * store of unconsumed enrollment tokens for host-mode ().
 *
 * Mirror of the daemon's `PendingTokensStore` from
 * `github/wireguardrtc` — same lifecycle (mint → lookup → consume),
 * same expiry purge on mint, same single-use semantics. Adapted to
 * Android conventions: single-process file (no flock), atomic
 * write via temp + rename, no replay-cache yet (deferred).
 */
class PendingTokensStoreTest {

    private fun store(dir: Path) = PendingTokensStore(File(dir.toFile(), "pending-tokens.json"))

    @Test fun `mint creates a fresh 32-byte token and persists it`(@TempDir dir: Path) {
        val s = store(dir)
        val now = 1_000_000L
        val tok = s.mint(nameHint = "alice", expiresInMs = 600_000L, now = now)
        assertEquals(32, tok.tokenSecret.size)
        assertEquals("alice", tok.nameHint)
        assertEquals(now, tok.mintedAtMs)
        assertEquals(now + 600_000L, tok.expiresAtMs)
        assertFalse(tok.consumed)

        // Reload from disk; should still be there.
        val s2 = store(dir)
        val all = s2.list(now = now + 1)
        assertEquals(1, all.size)
        assertArrayEquals(tok.tokenSecret, all[0].tokenSecret)
        assertEquals("alice", all[0].nameHint)
    }

    @Test fun `lookup finds a minted token, unknown token returns null`(@TempDir dir: Path) {
        val s = store(dir)
        val tok = s.mint("bob", 600_000L, now = 100L)
        assertNotNull(s.lookup(tok.tokenSecret, now = 200L))
        assertNull(s.lookup(ByteArray(32) { 0xFF.toByte() }, now = 200L))
    }

    @Test fun `lookup returns null for expired tokens`(@TempDir dir: Path) {
        val s = store(dir)
        val tok = s.mint("carol", expiresInMs = 100L, now = 1000L)
        // Just-in-time: still valid at expiresAt - 1ms.
        assertNotNull(s.lookup(tok.tokenSecret, now = 1099L))
        // Expired.
        assertNull(s.lookup(tok.tokenSecret, now = 1100L))
        assertNull(s.lookup(tok.tokenSecret, now = 999_999L))
    }

    @Test fun `consume marks token used and returns its state`(@TempDir dir: Path) {
        val s = store(dir)
        val tok = s.mint("dave", 600_000L, now = 100L)
        val consumed = s.consume(tok.tokenSecret, now = 200L)
        assertNotNull(consumed)
        assertEquals("dave", consumed!!.nameHint)
        assertFalse(consumed.consumed) // returns the PRIOR state
        // Lookup post-consume returns null (the daemon's TOKEN_USED flow
        // — single-use semantics).
        assertNull(s.lookup(tok.tokenSecret, now = 200L))
    }

    @Test fun `re-consume of a used token returns null`(@TempDir dir: Path) {
        val s = store(dir)
        val tok = s.mint("eve", 600_000L, now = 100L)
        assertNotNull(s.consume(tok.tokenSecret, now = 200L))
        assertNull(s.consume(tok.tokenSecret, now = 300L))
    }

    @Test fun `consume of expired token returns null`(@TempDir dir: Path) {
        val s = store(dir)
        val tok = s.mint("frank", expiresInMs = 100L, now = 1000L)
        assertNull(s.consume(tok.tokenSecret, now = 1100L))
        // Token was expired, never consumed.
        assertNull(s.lookup(tok.tokenSecret, now = 1100L))
    }

    @Test fun `purgeExpired removes only expired entries`(@TempDir dir: Path) {
        val s = store(dir)
        val a = s.mint("a", 100L, now = 1000L)
        val b = s.mint("b", 1000L, now = 1000L)
        val purged = s.purgeExpired(now = 1500L)
        assertEquals(1, purged)
        assertNull(s.lookup(a.tokenSecret, now = 1500L))
        assertNotNull(s.lookup(b.tokenSecret, now = 1500L))
    }

    @Test fun `mint purges expired tokens automatically`(@TempDir dir: Path) {
        val s = store(dir)
        s.mint("expiring", expiresInMs = 100L, now = 1000L)
        // Mint at a later time should have purged the expired one.
        s.mint("fresh", expiresInMs = 600_000L, now = 5000L)
        assertEquals(1, s.list(now = 5000L).size)
    }

    @Test fun `same name supersede replaces unconsumed unexpired token`(@TempDir dir: Path) {
        val s = store(dir)
        val first = s.mint("phone-laptop", 600_000L, now = 1000L)
        val second = s.mint("phone-laptop", 600_000L, now = 2000L)
        // Old token should be gone.
        assertNull(s.lookup(first.tokenSecret, now = 2000L))
        // New token is current.
        assertNotNull(s.lookup(second.tokenSecret, now = 2000L))
        assertEquals(1, s.list(now = 2000L).size)
    }

    @Test fun `mint enforces max-pending cap`(@TempDir dir: Path) {
        val s = store(dir)
        // Mint 4 tokens with cap=4 — last one should still succeed.
        repeat(4) { s.mint("name-$it", 600_000L, now = 1000L, maxPending = 4) }
        // 5th should refuse.
        assertThrows(IllegalStateException::class.java) {
            s.mint("over", 600_000L, now = 1000L, maxPending = 4)
        }
    }

    @Test fun `consumed tokens don't count against max-pending`(@TempDir dir: Path) {
        val s = store(dir)
        val a = s.mint("a", 600_000L, now = 1000L, maxPending = 2)
        s.mint("b", 600_000L, now = 1000L, maxPending = 2)
        // At cap. Consume one, then we should be able to mint again.
        s.consume(a.tokenSecret, now = 2000L)
        s.mint("c", 600_000L, now = 2000L, maxPending = 2)
        // Active list = b + c (a is consumed).
        val active = s.list(now = 2000L)
        assertEquals(2, active.size)
        assertEquals(setOf("b", "c"), active.map { it.nameHint }.toSet())
    }

    @Test fun `corrupt store file refuses to clobber, throws`(@TempDir dir: Path) {
        val f = File(dir.toFile(), "pending-tokens.json")
        f.writeText("{not valid json")
        val s = PendingTokensStore(f)
        assertThrows(IllegalStateException::class.java) {
            s.mint("foo", 600_000L, now = 1000L)
        }
        // File contents preserved (not silently overwritten).
        assertEquals("{not valid json", f.readText())
    }

    @Test fun `list returns empty on missing file`(@TempDir dir: Path) {
        val s = store(dir)
        assertTrue(s.list(now = 1000L).isEmpty())
    }
}
