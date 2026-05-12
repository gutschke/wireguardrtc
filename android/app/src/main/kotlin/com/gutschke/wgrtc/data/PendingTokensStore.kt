package com.gutschke.wgrtc.data

import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import java.security.SecureRandom
import java.util.Base64

/**
 * Phone-side storage of unconsumed (and recently-consumed) enrollment
 * tokens used by host-mode.
 *
 * Mirror of the daemon's `PendingTokensStore` in
 * `github/wireguardrtc`: same lifecycle (mint → lookup → consume),
 * same purge-on-mint, same single-use semantics, same
 * one-active-per-name supersede. Adapted to Android conventions:
 *
 * - Single-process: no `flock` (Android apps own their data dir).
 * - Atomic write via temp + rename.
 * - JSON via `kotlinx.serialization`; `encodeDefaults=true` so the
 * `consumed=false` discriminator survives the round-trip (see
 * `feedback_kotlinx_serialization_defaults` memory).
 * - No replay-cache yet. ENROLL_OK retry safety on the phone is
 * deferred — its main risk on the daemon was lost ENROLL_OK after
 * a network blip, which we'll address when the inbound-ENROLL
 * handler (3) ships.
 *
 * Pure JVM: takes a [File] (not Context), so unit tests under
 * `:app:test` exercise the same code path the runtime uses.
 */
class PendingTokensStore(private val file: File) {

    /** Persisted form of one token. */
    @Serializable
    data class Entry(
        /** URL-safe-base64 of the 32-byte raw token. */
        val tokenB64: String,
        val nameHint: String,
        val mintedAtMs: Long,
        val expiresAtMs: Long,
        val consumed: Boolean = false,
    )

    /** Snapshot of an active (or freshly-consumed) token, exposed to callers. */
    data class PendingToken(
        val tokenSecret: ByteArray,
        val nameHint: String,
        val mintedAtMs: Long,
        val expiresAtMs: Long,
        val consumed: Boolean,
    ) {
        // ByteArray equals/hashCode would be reference-based by default;
        // we override so tests can compare two snapshots structurally.
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is PendingToken) return false
            return tokenSecret.contentEquals(other.tokenSecret) &&
                nameHint == other.nameHint &&
                mintedAtMs == other.mintedAtMs &&
                expiresAtMs == other.expiresAtMs &&
                consumed == other.consumed
        }
        override fun hashCode(): Int = tokenSecret.contentHashCode()
    }

    @Serializable
    private data class State(
        val version: Int = 1,
        val tokens: List<Entry> = emptyList(),
    )

    private val json = Json {
        encodeDefaults = true // consumed=false must survive the round-trip
        prettyPrint = true
    }

    private val rng = SecureRandom()

    @Synchronized
    fun mint(
        nameHint: String,
        expiresInMs: Long,
        now: Long,
        maxPending: Int = 32,
    ): PendingToken {
        require(expiresInMs > 0L) { "expiresInMs must be positive" }
        require(maxPending in 1..1000) { "maxPending out of range" }
        val state = load()

        // 1. Purge expired and consumed entries kept around for diagnostics.
        val purged = state.tokens.filter { e -> !e.consumed && e.expiresAtMs > now }

        // 2. Same-name supersede: drop any existing unconsumed unexpired
        // token with the same name.
        val afterSupersede = purged.filter { it.nameHint != nameHint }

        // 3. Enforce max-pending against the post-supersede list.
        if (afterSupersede.size >= maxPending) {
            throw IllegalStateException(
                "max-pending cap reached: $maxPending unconsumed tokens already pending")
        }

        // 4. Generate the new token.
        val secret = ByteArray(TOKEN_BYTES).also { rng.nextBytes(it) }
        val entry = Entry(
            tokenB64 = b64.encodeToString(secret),
            nameHint = nameHint,
            mintedAtMs = now,
            expiresAtMs = now + expiresInMs,
            consumed = false,
        )
        save(state.copy(tokens = afterSupersede + entry))
        return entry.toToken(secret)
    }

    @Synchronized
    fun lookup(tokenSecret: ByteArray, now: Long): PendingToken? {
        val state = load()
        val tokB64 = b64.encodeToString(tokenSecret)
        val e = state.tokens.firstOrNull { it.tokenB64 == tokB64 } ?: return null
        if (e.consumed) return null
        if (e.expiresAtMs <= now) return null
        return e.toToken(tokenSecret)
    }

    /**
     * Mark [tokenSecret] consumed. Returns the entry's *prior* state
     * (so the caller can act on its `nameHint`, expiry, etc.) or null
     * if the token was unknown / already-consumed / expired.
     */
    @Synchronized
    fun consume(tokenSecret: ByteArray, now: Long): PendingToken? {
        val state = load()
        val tokB64 = b64.encodeToString(tokenSecret)
        val idx = state.tokens.indexOfFirst { it.tokenB64 == tokB64 }
        if (idx < 0) return null
        val e = state.tokens[idx]
        if (e.consumed) return null
        if (e.expiresAtMs <= now) return null
        val updated = e.copy(consumed = true)
        save(state.copy(tokens = state.tokens.toMutableList().also { it[idx] = updated }))
        return e.toToken(tokenSecret) // PRIOR state
    }

    /** Drop expired tokens. Returns the count removed. */
    @Synchronized
    fun purgeExpired(now: Long): Int {
        val state = load()
        val kept = state.tokens.filter { e -> e.consumed || e.expiresAtMs > now }
        val n = state.tokens.size - kept.size
        if (n > 0) save(state.copy(tokens = kept))
        return n
    }

    /** All currently-active (unconsumed, unexpired) tokens. */
    @Synchronized
    fun list(now: Long): List<PendingToken> {
        val state = load()
        return state.tokens
            .filter { !it.consumed && it.expiresAtMs > now }
            .map { it.toToken(b64.decode(it.tokenB64)) }
    }

    /**
     * All non-expired entries — including consumed ones. Used by the
     * inbound-ENROLL handler so a re-enrollment with a token someone
     * else just claimed gets an authenticated `TOKEN_USED` reply
     * instead of the silent "no matching token" path (mirrors the
     * daemon's [_handle_enroll] which try-decrypts over both used and
     * unused tokens for exactly this reason).
     */
    @Synchronized
    fun listAll(now: Long): List<PendingToken> {
        val state = load()
        return state.tokens
            .filter { it.expiresAtMs > now }
            .map { it.toToken(b64.decode(it.tokenB64)) }
    }

    // ── internals ────────────────────────────────────────────────────

    private fun Entry.toToken(secret: ByteArray) = PendingToken(
        tokenSecret = secret,
        nameHint = nameHint,
        mintedAtMs = mintedAtMs,
        expiresAtMs = expiresAtMs,
        consumed = consumed,
    )

    private fun load(): State {
        if (!file.exists()) return State()
        val text = file.readText()
        if (text.isBlank()) return State()
        return try {
            json.decodeFromString(State.serializer(), text)
        } catch (e: SerializationException) {
            throw IllegalStateException(
                "corrupt ${file.path}: ${e.message}; refusing to overwrite", e)
        }
    }

    private fun save(state: State) {
        file.parentFile?.mkdirs()
        val tmp = File(file.parentFile, "${file.name}.tmp")
        tmp.writeText(json.encodeToString(State.serializer(), state))
        // Atomic rename — POSIX semantics; on Android this is the
        // standard way single-writer state survives crashes.
        if (!tmp.renameTo(file)) {
            // Fallback for cases where rename can't replace existing
            // (rare on Android; happens on some FS layouts).
            tmp.copyTo(file, overwrite = true)
            tmp.delete()
        }
    }

    companion object {
        const val TOKEN_BYTES: Int = 32
        private val b64 = Base64.getUrlEncoder().withoutPadding()
    }
}

private fun Base64.Encoder.encodeToString(bytes: ByteArray): String =
    this.encodeToString(bytes)

private fun Base64.Encoder.decode(text: String): ByteArray =
    Base64.getUrlDecoder().decode(text)
