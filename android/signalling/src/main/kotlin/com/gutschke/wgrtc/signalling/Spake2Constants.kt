package com.gutschke.wgrtc.signalling

/**
 * Domain-separated SPAKE2 blinding constants M and N for
 * Ristretto255. Each is a 32-byte canonical Ristretto255 encoding,
 * derived deterministically by hashing a label string and feeding
 * the result through Ristretto255's `from_hash` (uniform random
 * curve-point construction).
 *
 * Both sides of the protocol must agree on these bytes byte-for-
 * byte. Bumping either label string changes the constant and is a
 * **wire-incompatible** protocol change — peers built against
 * different labels won't interoperate.
 *
 * Why lazy + cached, rather than hard-coded literals: the
 * derivation is deterministic, and the same code on both sides
 * produces the same bytes. We cache the value in `lazy` so the
 * 64-byte BLAKE2b + Ristretto255 from_hash only run once per
 * process. A future audit-hardening step is to run the derivation
 * once, hard-code the 32 hex bytes for each, and remove the
 * runtime computation; until then this keeps the surface tiny and
 * verifiable from one place.
 */
internal object Spake2Constants {
    /** Alice's password-blinding factor. */
    val M: ByteArray by lazy { deriveRistretto255Point(M_LABEL) }
    /** Bob's password-blinding factor. */
    val N: ByteArray by lazy { deriveRistretto255Point(N_LABEL) }

    private val M_LABEL: ByteArray = "wgrtc/spake2/M-2026".toByteArray(Charsets.UTF_8)
    private val N_LABEL: ByteArray = "wgrtc/spake2/N-2026".toByteArray(Charsets.UTF_8)

    /** Map [label] to a uniformly-random Ristretto255 point.
     * blake2b(label) → 64 bytes → ristretto_from_hash → 32-byte point. */
    private fun deriveRistretto255Point(label: ByteArray): ByteArray {
        val h64 = ByteArray(64)
        val ok = Sodium.instance.cryptoGenericHash(
            h64, h64.size, label, label.size.toLong(),
            // No keying — different labels are sufficient for
            // separation; the Ristretto255 step adds collision
            // resistance.
            null, 0,
        )
        check(ok) { "blake2b(label=${String(label, Charsets.UTF_8)}) failed" }
        val point = ByteArray(32)
        check(Sodium.instance.cryptoCoreRistretto255FromHash(point, h64)) {
            "ristretto255_from_hash failed for ${String(label, Charsets.UTF_8)}"
        }
        check(Sodium.instance.cryptoCoreRistretto255IsValidPoint(point)) {
            "derived M/N must be a valid Ristretto255 point"
        }
        return point
    }
}
