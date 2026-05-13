package com.gutschke.wgrtc.signalling

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.SecureRandom

class WormholeCodeTest {

    @Test fun `generate yields the requested length`() {
        val rng = SecureRandom.getInstance("SHA1PRNG").also { it.setSeed(42) }
        repeat(20) {
            val c = WormholeCode.generate(length = 6, rng = rng)
            assertEquals(6, c.length)
        }
    }

    @Test fun `generate uses only ALPHABET characters`() {
        val rng = SecureRandom.getInstance("SHA1PRNG").also { it.setSeed(7) }
        repeat(50) {
            val c = WormholeCode.generate(length = 8, rng = rng)
            assertTrue(c.all { it in WormholeCode.ALPHABET },
                "code $c contains characters outside the alphabet")
        }
    }

    @Test fun `ALPHABET excludes I and O`() {
        // Visual-confusion guard: I looks like 1, O looks like 0.
        // Confirm both are absent so generated codes never include them.
        assertFalse(WormholeCode.ALPHABET.contains('I'))
        assertFalse(WormholeCode.ALPHABET.contains('O'))
        // Sanity: alphabet still has 24 letters.
        assertEquals(24, WormholeCode.ALPHABET.length)
    }

    @Test fun `generate rejects out-of-range lengths`() {
        assertThrows(IllegalArgumentException::class.java) { WormholeCode.generate(length = 0) }
        assertThrows(IllegalArgumentException::class.java) { WormholeCode.generate(length = 33) }
    }

    @Test fun `normalize uppercases and strips spaces and dashes`() {
        assertEquals("ABCDEF", WormholeCode.normalize("ab-cd ef"))
        assertEquals("ABCDEF", WormholeCode.normalize("ABC-DEF"))
        assertEquals("ABCDEF", WormholeCode.normalize(" a b c d e f "))
    }

    @Test fun `normalize drops disallowed characters (digits, I, O, etc)`() {
        // Digit zero, the letter I, the letter O — all stripped.
        assertEquals("ABCDEF", WormholeCode.normalize("AB0CDIEF"))
        assertEquals("ABCDEF", WormholeCode.normalize("AB.CD-EF"))
        // Lowercase 'l' uppercases to 'L' which IS in the alphabet,
        // so it survives normalization. Lowercase 'i' uppercases to
        // 'I' which is NOT in the alphabet, so it gets dropped.
        assertEquals("ABCDEFL", WormholeCode.normalize("aBcDeFiOl"))
        assertEquals("ABCDEFL", WormholeCode.normalize("aBcDeFil"))
    }

    @Test fun `isValid accepts a 6-character normalized code`() {
        assertTrue(WormholeCode.isValid("ABCDEF"))
        assertTrue(WormholeCode.isValid("ab-cdef")) // normalized before check
        assertTrue(WormholeCode.isValid("ABC DEF"))
    }

    @Test fun `isValid rejects too-short or too-long codes`() {
        assertFalse(WormholeCode.isValid("ABCDE")) // 5 letters
        assertFalse(WormholeCode.isValid("ABCDEFG")) // 7
        assertFalse(WormholeCode.isValid(""))
    }

    @Test fun `isValid rejects junk that normalises to fewer characters`() {
        // "AB!@#" normalises to "AB" (2 letters) — too short.
        assertFalse(WormholeCode.isValid("AB!@#"))
    }

    @Test fun `toBytes returns canonical UTF-8 bytes`() {
        assertArrayEquals("ABCDEF".toByteArray(Charsets.UTF_8),
            WormholeCode.toBytes("ABCDEF"))
        // Same canonical bytes regardless of input formatting.
        assertArrayEquals(
            WormholeCode.toBytes("ABCDEF"),
            WormholeCode.toBytes("ab-cdef"),
        )
    }

    @Test fun `toBytes is idempotent across normalized vs raw input`() {
        val raw = " AB-CDEF "
        val once = WormholeCode.toBytes(raw)
        val twice = WormholeCode.toBytes(WormholeCode.normalize(raw))
        assertArrayEquals(once, twice)
    }

    @Test fun `two generates with different seeds produce different codes`() {
        val a = WormholeCode.generate(rng = SecureRandom.getInstance("SHA1PRNG").also { it.setSeed(1) })
        val b = WormholeCode.generate(rng = SecureRandom.getInstance("SHA1PRNG").also { it.setSeed(2) })
        assertNotEquals(a, b)
    }
}
