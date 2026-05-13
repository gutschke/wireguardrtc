package com.gutschke.wgrtc.signalling

import java.security.SecureRandom

/**
 * Wormhole-code generator + normalizer for SAS-based
 * enrollment. The "code" is the SPAKE2 password — short enough for
 * a human to read aloud or type, long enough that a brute-force
 * attacker can't enumerate it within the broker's rate-limit
 * window before the user notices and aborts.
 *
 * **Format**: 6 uppercase letters from a 24-letter alphabet (the
 * standard A–Z minus 'I' and 'O', which look like 1 and 0 in many
 * fonts). Search space is 24^6 ≈ 191 million. Combined with the
 * one-attempt-per-mint-cycle threat model from
 * [Spake2Sas.deriveSas]'s SAS step, the practical attack is
 * one-shot: an attacker has to guess correctly on the first try,
 * which the human SAS-confirmation catches if they don't.
 *
 * **Normalization**: the user's typed input goes through [normalize]
 * before any comparison or [toBytes]. Both sides MUST use the same
 * canonical form, otherwise SPAKE2 produces different keys (which
 * the SAS catches, but only after both sides go through the
 * full handshake). Canonical form = uppercase, with whitespace
 * and dashes stripped.
 *
 * **Wire bytes**: ASCII (UTF-8 of the canonical string) — no length
 * prefix, no terminator. The SPAKE2 layer hashes them through a
 * domain-separation label so the *bytes* don't collide with any
 * other use of the same characters.
 */
object WormholeCode {
    /** 24 uppercase letters: A–Z minus I and O. */
    const val ALPHABET: String = "ABCDEFGHJKLMNPQRSTUVWXYZ"

    /** Default length. Changing this is a UX change, not a wire-
     * format change — peers can speak any length as long as both
     * sides use the same input. */
    const val DEFAULT_LENGTH: Int = 6

    /** Generate a uniformly-random code from [ALPHABET]. Uses
     * rejection-free indexing because [ALPHABET].length divides
     * evenly into a small enough space. */
    fun generate(length: Int = DEFAULT_LENGTH, rng: SecureRandom = SecureRandom()): String {
        require(length in 1..32) { "length out of range (got $length, allowed 1..32)" }
        val sb = StringBuilder(length)
        repeat(length) { sb.append(ALPHABET[rng.nextInt(ALPHABET.length)]) }
        return sb.toString()
    }

    /**
     * Canonicalise a user-typed code: uppercase, drop whitespace +
     * dashes, drop any character not in [ALPHABET] (typos like
     * the digit zero get stripped — better than letting them slip
     * into the SPAKE2 password and yielding a guaranteed mismatch).
     */
    fun normalize(raw: String): String =
        raw.uppercase()
            .filter { it in ALPHABET }

    /** True iff [code] (normalized) is exactly [length] letters
     * long. Use this to decide whether to enable a "Continue"
     * button. */
    fun isValid(code: String, length: Int = DEFAULT_LENGTH): Boolean {
        val n = normalize(code)
        return n.length == length
    }

    /** Convert a normalized code to the bytes SPAKE2 will hash.
     * Caller's responsibility to pass [normalize]'d input — but
     * this method normalizes again as defense-in-depth so a UI
     * bug can't silently produce a non-canonical byte string. */
    fun toBytes(code: String): ByteArray =
        normalize(code).toByteArray(Charsets.UTF_8)
}
