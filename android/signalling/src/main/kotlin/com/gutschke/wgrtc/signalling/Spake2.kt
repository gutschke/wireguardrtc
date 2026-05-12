package com.gutschke.wgrtc.signalling

/**
 * SPAKE2 (RFC 9382) over Ristretto255, pure Kotlin.
 *
 * wormhole-code enrolment uses this PAKE: both sides know a
 * low-entropy code (e.g. 6 letters); the protocol upgrades that into
 * a 256-bit shared key without leaking the code on the wire. An
 * attacker who relays one half but not the other can complete the
 * PAKE on each side independently — they'll arrive at *different*
 * shared keys, which the user-confirmation SAS step catches.
 *
 * **Why Ristretto255**: Curve25519 has cofactor 8 — a known footgun
 * for protocols (like SPAKE2) that assume a clean prime-order group.
 * Ristretto255 is a prime-order group built on top of Curve25519
 * specifically to eliminate cofactor pitfalls. All point encodings
 * are canonical; small-subgroup attacks don't apply; the
 * `from_hash` operation gives us a uniform-random curve point.
 *
 * **Protocol shape** (mirrors RFC 9382 §3.2):
 *
 * pwScalar = scalarReduce(blake2b(password, key=LABEL_SPAKE2_PW, 64))
 * privScalar = random scalar
 *
 * Alice sends: X = privScalar*G + pwScalar*M
 * Bob sends: Y = privScalar*G + pwScalar*N
 *
 * Alice computes: K = privScalar * (Y - pwScalar*N)
 * Bob computes: K = privScalar * (X - pwScalar*M)
 *
 * sessionKey = blake2b(transcript || K, key=LABEL_SPAKE2_KEY, 32)
 *
 * with M and N a pair of distinct, deterministically-derived
 * Ristretto255 points (see [Spake2Constants]). Transcript ordering
 * is canonical across roles so both sides hash the same bytes.
 *
 * **Threat model + non-goals**:
 * - The *protocol* is constant-time-by-construction (all libsodium
 * primitives are constant-time). Higher layers (broker rate
 * limiting, manual SAS confirmation) defend against online-
 * guessing attacks.
 * - This class does **not** include a key-confirmation step. The
 * intended caller derives the SAS from the returned key (see
 * [Spake2Sas.deriveSas]) and the user manually confirms.
 * - **Single-use per instance** — call `start()` once, then
 * `finish(peer)` once. Reusing instances is rejected.
 *
 * **Wire bytes** are 32-byte messages (Ristretto255 points). No
 * extra framing — the OFFER envelope's `metadata.kind = sas_step_*`
 * carries the bytes.
 *
 * **Test seam**: replace [Sodium.instance] via [Sodium.setForTest]
 * for JVM unit tests using lazysodium-java.
 */
class Spake2(
    private val role: Role,
    password: ByteArray,
    private val idA: ByteArray = ByteArray(0),
    private val idB: ByteArray = ByteArray(0),
) {
    enum class Role { ALICE, BOB }

    private val privScalar: ByteArray = ByteArray(SCALAR_BYTES)
    private val pwScalar: ByteArray = ByteArray(SCALAR_BYTES)
    private var sentMessage: ByteArray? = null
    private var startCalled = false

    init {
        val s = Sodium.instance
        // Random per-session ephemeral scalar.
        s.cryptoCoreRistretto255ScalarRandom(privScalar)
        // Map the password into the scalar field via a 64-byte hash
        // → reduce mod L. BLAKE2b keyed by LABEL_SPAKE2_PW is our
        // domain separator; the same password used in another
        // protocol with a different label yields a different scalar.
        val h64 = ByteArray(HASH_BYTES_64)
        val ok = Sodium.instance.cryptoGenericHash(
            h64, h64.size, password, password.size.toLong(),
            LABEL_SPAKE2_PW, LABEL_SPAKE2_PW.size,
        )
        check(ok) { "blake2b(password) failed" }
        s.cryptoCoreRistretto255ScalarReduce(pwScalar, h64)
    }

    /**
     * Generate this side's outgoing message. Returns 32 bytes —
     * the Ristretto255-encoded curve point to deliver to the peer.
     */
    fun start(): ByteArray {
        check(!startCalled) { "start() may only be called once per Spake2 instance" }
        startCalled = true
        val s = Sodium.instance
        // privPart = privScalar * G (G is the standard Ristretto255 generator).
        val privPart = ByteArray(POINT_BYTES)
        check(s.cryptoScalarmultRistretto255Base(privPart, privScalar)) {
            "scalarmult-base failed"
        }
        // pwPart = pwScalar * (this side's blinding factor: M for Alice, N for Bob).
        val blinding = if (role == Role.ALICE) Spake2Constants.M else Spake2Constants.N
        val pwPart = ByteArray(POINT_BYTES)
        check(s.cryptoScalarmultRistretto255(pwPart, pwScalar, blinding)) {
            "scalarmult M/N failed"
        }
        // X = privPart + pwPart.
        val msg = ByteArray(POINT_BYTES)
        check(s.cryptoCoreRistretto255Add(msg, privPart, pwPart)) {
            "ristretto add failed"
        }
        sentMessage = msg
        return msg.copyOf()
    }

    /**
     * Given the peer's outgoing message, derive the 32-byte shared
     * session key. Both sides arrive at the same key iff they used
     * the same password AND complementary roles.
     *
     * Throws on:
     * - [start] not called yet,
     * - peer message wrong size or not a valid Ristretto255 point,
     * - any libsodium primitive failure (expected to be impossible
     * for valid inputs but checked defensively).
     */
    fun finish(peerMessage: ByteArray): ByteArray {
        val sentMsg = sentMessage
            ?: error("call start() before finish()")
        require(peerMessage.size == POINT_BYTES) {
            "peer message must be $POINT_BYTES bytes (got ${peerMessage.size})"
        }
        val s = Sodium.instance
        check(s.cryptoCoreRistretto255IsValidPoint(peerMessage)) {
            "peer message is not a valid Ristretto255 point"
        }
        // peerBlinding = peer's M-or-N. Roles are complementary:
        // if I'm Alice, peer is Bob (or claims to be) → peer used N.
        val peerBlinding = if (role == Role.ALICE) Spake2Constants.N else Spake2Constants.M
        val peerPwPart = ByteArray(POINT_BYTES)
        check(s.cryptoScalarmultRistretto255(peerPwPart, pwScalar, peerBlinding)) {
            "scalarmult peer M/N failed"
        }
        // unmasked = peerMessage - peerPwPart. If peer used the same
        // password, this equals peer's privScalar * G.
        val unmasked = ByteArray(POINT_BYTES)
        check(s.cryptoCoreRistretto255Sub(unmasked, peerMessage, peerPwPart)) {
            "ristretto sub failed"
        }
        // K = privScalar * unmasked. Shared point iff passwords match.
        val k = ByteArray(POINT_BYTES)
        check(s.cryptoScalarmultRistretto255(k, privScalar, unmasked)) {
            "k = priv*unmasked failed"
        }
        // Transcript: idA || idB || msgA || msgB || pwScalar || K.
        // Role-canonical so both sides hash the same bytes.
        val msgA = if (role == Role.ALICE) sentMsg else peerMessage
        val msgB = if (role == Role.ALICE) peerMessage else sentMsg
        val transcript = ByteArray(
            idA.size + idB.size + msgA.size + msgB.size + pwScalar.size + k.size
        )
        var off = 0
        idA.copyInto(transcript, off); off += idA.size
        idB.copyInto(transcript, off); off += idB.size
        msgA.copyInto(transcript, off); off += msgA.size
        msgB.copyInto(transcript, off); off += msgB.size
        pwScalar.copyInto(transcript, off); off += pwScalar.size
        k.copyInto(transcript, off)
        val out = ByteArray(KEY_BYTES_32)
        check(Sodium.instance.cryptoGenericHash(
            out, out.size, transcript, transcript.size.toLong(),
            LABEL_SPAKE2_KEY, LABEL_SPAKE2_KEY.size,
        )) { "blake2b(transcript) failed" }
        return out
    }

    companion object {
        private const val POINT_BYTES = 32
        private const val SCALAR_BYTES = 32
        private const val HASH_BYTES_64 = 64
        private const val KEY_BYTES_32 = 32
        // Domain-separation labels. Don't change without bumping the
        // protocol version — both sides MUST agree.
        internal val LABEL_SPAKE2_PW: ByteArray = "wgrtc/spake2/pw-2026".toByteArray(Charsets.UTF_8)
        internal val LABEL_SPAKE2_KEY: ByteArray = "wgrtc/spake2/key-2026".toByteArray(Charsets.UTF_8)
    }
}
