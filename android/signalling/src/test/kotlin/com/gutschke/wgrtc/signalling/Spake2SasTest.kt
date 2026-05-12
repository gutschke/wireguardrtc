package com.gutschke.wgrtc.signalling

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class Spake2SasTest {

    @BeforeAll fun installJvmSodium() {
        Sodium.setForTest(LazySodiumJava(SodiumJava()))
    }
    @AfterAll fun restoreSodium() { Sodium.setForTest(null) }

    @Test fun `same key produces same SAS`() {
        val k = ByteArray(32) { it.toByte() }
        assertEquals(deriveSas(k), deriveSas(k))
    }

    @Test fun `different keys produce different SAS`() {
        val k1 = ByteArray(32) { it.toByte() }
        val k2 = ByteArray(32) { (it + 1).toByte() }
        assertNotEquals(deriveSas(k1), deriveSas(k2))
    }

    @Test fun `default SAS has four space-separated words`() {
        val k = ByteArray(32) { 0x42.toByte() }
        val sas = deriveSas(k)
        val words = sas.split(' ')
        assertEquals(4, words.size, "expected 4 words, got '$sas'")
        // Each word is a non-empty token.
        assertTrue(words.all { it.isNotEmpty() })
    }

    @Test fun `SAS words come from the configured wordlist`() {
        val k = ByteArray(32) { 0x99.toByte() }
        val sas = deriveSas(k)
        val words = sas.split(' ')
        assertTrue(words.all { it in PLACEHOLDER_SAS_WORDLIST },
            "expected all SAS words from PLACEHOLDER_SAS_WORDLIST; got: $sas")
    }

    @Test fun `wordCount=2 emits exactly two words`() {
        val k = ByteArray(32) { 0x10.toByte() }
        val sas = deriveSas(k, wordCount = 2)
        assertEquals(2, sas.split(' ').size)
    }

    @Test fun `wordCount=8 emits exactly eight words`() {
        val k = ByteArray(32) { 0x20.toByte() }
        val sas = deriveSas(k, wordCount = 8)
        assertEquals(8, sas.split(' ').size)
    }

    @Test fun `wordCount=0 yields empty string`() {
        val k = ByteArray(32) { 0xFF.toByte() }
        assertEquals("", deriveSas(k, wordCount = 0))
    }

    @Test fun `key must be at least 16 bytes for safety`() {
        // Below 16 bytes the SAS wouldn't be derived from a
        // cryptographic-strength input. Defensive guard.
        assertThrows(IllegalArgumentException::class.java) {
            deriveSas(ByteArray(8))
        }
    }

    @Test fun `wordlist is exactly 256 entries (one byte per word)`() {
        // Property the wordlist must keep so 8-bit indexing works.
        // If we ever swap to PGP-words this test still passes (PGP
        // even/odd are 256 each).
        assertEquals(256, PLACEHOLDER_SAS_WORDLIST.size)
        // No duplicates — each byte → distinct word.
        assertEquals(PLACEHOLDER_SAS_WORDLIST.size,
                     PLACEHOLDER_SAS_WORDLIST.toSet().size,
                     "PLACEHOLDER_SAS_WORDLIST has duplicates")
        // No spaces inside any word — they're space-joined.
        assertTrue(PLACEHOLDER_SAS_WORDLIST.none { ' ' in it })
        // Reasonable length range.
        assertTrue(PLACEHOLDER_SAS_WORDLIST.all { it.length in 2..12 })
    }

    @Test fun `SPAKE2 round-trip → matching SAS on both sides`() {
        // The user-confirmation contract: both sides display the
        // same SAS phrase iff they completed the PAKE with matching
        // passwords + roles.
        val code = "tangerine-ferret-3".toByteArray()
        val alice = Spake2(Spake2.Role.ALICE, code)
        val bob = Spake2(Spake2.Role.BOB, code)
        val msgA = alice.start()
        val msgB = bob.start()
        val keyA = alice.finish(msgB)
        val keyB = bob.finish(msgA)
        assertArrayEquals(keyA, keyB)
        assertEquals(deriveSas(keyA), deriveSas(keyB))
    }

    @Test fun `SPAKE2 mismatched code → different SAS on each side`() {
        val codeA = "real".toByteArray()
        val codeB = "wrong".toByteArray()
        val alice = Spake2(Spake2.Role.ALICE, codeA)
        val bob = Spake2(Spake2.Role.BOB, codeB)
        val msgA = alice.start()
        val msgB = bob.start()
        val keyA = alice.finish(msgB)
        val keyB = bob.finish(msgA)
        assertNotEquals(deriveSas(keyA), deriveSas(keyB),
            "SAS difference is exactly the user-visible signal that the code was wrong")
    }
}
