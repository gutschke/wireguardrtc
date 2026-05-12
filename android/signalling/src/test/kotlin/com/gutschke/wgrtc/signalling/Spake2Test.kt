package com.gutschke.wgrtc.signalling

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance

/**
 * Symmetric SPAKE2 round-trip + adversarial cases.
 *
 * Wire format under test:
 *
 * Alice Bob
 * ───── ───
 * start() → X start() → Y
 * send X to Bob | send Y to Alice
 * finish(Y) → K | finish(X) → K ← both sides arrive at the same K
 * iff they used the same password.
 *
 * The protocol is symmetric: ALICE and BOB are interchangeable
 * roles that just rotate which of M / N each side uses as their
 * password-blinding factor. Matching peer roles is required
 * (Alice with Bob, not Alice with Alice).
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class Spake2Test {

    @BeforeAll fun installJvmSodium() {
        Sodium.setForTest(LazySodiumJava(SodiumJava()))
    }
    @AfterAll fun restoreSodium() { Sodium.setForTest(null) }

    private fun pw(s: String) = s.toByteArray(Charsets.UTF_8)

    // ─── happy path ────────────────────────────────────────────────────

    @Test fun `round-trip — same password yields the same shared key`() {
        val code = pw("orange-bicycle-9")
        val alice = Spake2(Spake2.Role.ALICE, code, idA = "alice".toByteArray(), idB = "bob".toByteArray())
        val bob = Spake2(Spake2.Role.BOB, code, idA = "alice".toByteArray(), idB = "bob".toByteArray())

        val msgA = alice.start()
        val msgB = bob.start()

        val keyA = alice.finish(msgB)
        val keyB = bob.finish(msgA)

        assertArrayEquals(keyA, keyB)
        assertEquals(32, keyA.size)
    }

    @Test fun `each session uses fresh randomness — same password gives different keys per session`() {
        val code = pw("magenta-llama-7")
        val (k1A, k1B) = fullExchange(code)
        val (k2A, k2B) = fullExchange(code)
        // Within each session, A and B agree.
        assertArrayEquals(k1A, k1B)
        assertArrayEquals(k2A, k2B)
        // Across sessions, the keys differ — fresh ephemeral scalars.
        assertFalse(k1A.contentEquals(k2A),
            "expected fresh per-session randomness; got identical keys")
    }

    @Test fun `binding to ids — different ids produce different keys`() {
        val code = pw("cobalt-walrus-4")
        val (k1A, _) = fullExchange(code, idA = "phone-A", idB = "phone-B")
        val (k2A, _) = fullExchange(code, idA = "phone-A", idB = "phone-X")
        // The transcript includes idA / idB; changing them must
        // affect the final key.
        assertFalse(k1A.contentEquals(k2A),
            "id binding must contribute to the final key")
    }

    // ─── adversarial / mismatch ────────────────────────────────────────

    @Test fun `wrong password — different keys derived on each side`() {
        val alice = Spake2(Spake2.Role.ALICE, pw("real-code"))
        val bob = Spake2(Spake2.Role.BOB, pw("wrong-code"))
        val msgA = alice.start()
        val msgB = bob.start()
        val keyA = alice.finish(msgB)
        val keyB = bob.finish(msgA)
        assertFalse(keyA.contentEquals(keyB),
            "wrong password must yield different K on each side; SAS confirmation catches this")
    }

    @Test fun `peer message must be 32 bytes`() {
        val alice = Spake2(Spake2.Role.ALICE, pw("x"))
        alice.start()
        assertThrows(IllegalArgumentException::class.java) {
            alice.finish(ByteArray(31))
        }
        assertThrows(IllegalArgumentException::class.java) {
            alice.finish(ByteArray(33))
        }
    }

    @Test fun `peer message that decodes to invalid Ristretto255 point is rejected`() {
        val alice = Spake2(Spake2.Role.ALICE, pw("y"))
        alice.start()
        // All-0xFF is overwhelmingly likely to be an invalid Ristretto255
        // encoding (the encoding has structural constraints). finish()
        // should detect and refuse.
        val bogus = ByteArray(32) { 0xFF.toByte() }
        assertThrows(IllegalStateException::class.java) {
            alice.finish(bogus)
        }
    }

    @Test fun `start must be called before finish`() {
        val alice = Spake2(Spake2.Role.ALICE, pw("z"))
        assertThrows(IllegalStateException::class.java) {
            alice.finish(ByteArray(32))
        }
    }

    @Test fun `start can only be called once`() {
        val alice = Spake2(Spake2.Role.ALICE, pw("a"))
        alice.start()
        assertThrows(IllegalStateException::class.java) { alice.start() }
    }

    @Test fun `start produces a valid Ristretto255 point`() {
        val alice = Spake2(Spake2.Role.ALICE, pw("b"))
        val msg = alice.start()
        assertEquals(32, msg.size)
        assertTrue(Sodium.instance.cryptoCoreRistretto255IsValidPoint(msg),
            "start() output must be a valid Ristretto255 point")
    }

    @Test fun `role mismatch — both sides ALICE — different keys`() {
        val code = pw("c")
        val a1 = Spake2(Spake2.Role.ALICE, code)
        val a2 = Spake2(Spake2.Role.ALICE, code)
        val m1 = a1.start()
        val m2 = a2.start()
        val k1 = a1.finish(m2)
        val k2 = a2.finish(m1)
        // Both used M as their blinding factor → the unmasking
        // arithmetic doesn't cancel correctly → K_a != K_b.
        assertFalse(k1.contentEquals(k2),
            "role mismatch must not yield matching keys")
    }

    // ─── helpers ───────────────────────────────────────────────────────

    /** Run a full Alice/Bob exchange and return the derived keys.
     * Returns (Alice's K, Bob's K). Same-password / same-ids should
     * produce equal keys. */
    private fun fullExchange(
        code: ByteArray, idA: String = "", idB: String = "",
    ): Pair<ByteArray, ByteArray> {
        val alice = Spake2(Spake2.Role.ALICE, code,
            idA.toByteArray(), idB.toByteArray())
        val bob = Spake2(Spake2.Role.BOB, code,
            idA.toByteArray(), idB.toByteArray())
        val msgA = alice.start()
        val msgB = bob.start()
        return alice.finish(msgB) to bob.finish(msgA)
    }
}
