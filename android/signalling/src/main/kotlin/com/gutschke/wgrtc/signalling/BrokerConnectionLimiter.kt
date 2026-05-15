package com.gutschke.wgrtc.signalling

import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Global per-broker WSS connection rate limiter.
 *
 * Every code path that opens a WSS to a PeerJS broker must call
 * [acquire] before issuing `httpClient.newWebSocket(...)`. The
 * limiter ensures at most one connection-open per
 * [MIN_INTERVAL_MS] per broker URL across the entire app —
 * preventing the public broker (which is Cloudflare-fronted at
 * `0.peerjs.com` and rate-limits at ~5 conn/sec) from issuing a
 * 429 against us due to misbehaving callers.
 *
 * History: a cancel-restart cascade in WgrtcViewModel
 * (2026-05-08, fixed) was opening 5–10 WSS connections per second
 * during VPN setup events. Cloudflare blocked us with HTTP 429,
 * which broke enrollment for ~1 hour. This limiter is the
 * belt-and-suspenders against any future bug producing a similar
 * pattern.
 *
 * **Server side does NOT need an equivalent.** The daemon
 * (`wireguardrtc`'s `PeerJSClient`) maintains exactly ONE
 * long-lived WSS per process; reconnect storms are already gated
 * by `STABLE_SESSION_S` (CR-D9). The daemon never opens per-peer
 * WSS — `signal_peer` sends via the existing connection — so a
 * single backoff guard is sufficient.
 *
 * The two callers on Android that still open new WSS connections:
 * - [OfferListener] — long-lived WSS per ENROLL tunnel
 * (one per tunnel). Reconnect backoff layered on top of this
 * limiter, since reconnect attempts are themselves WSS opens.
 * - [EnrollClient] — one-shot WSS per Add-Tunnel; user-driven
 * so rare, but bursts during user retry on transient errors
 * can stack.
 *
 * [OfferSender.sendWake] does NOT use the limiter — wakes ride the
 * existing listener WSS via [OfferListener.sendThrough], which
 * doesn't open a new connection. Earlier versions opened a one-shot
 * WSS per wake (under a random id, to avoid kicking the listener);
 * that registered the wake under a broker id the daemon couldn't
 * dispatch on, so the daemon silently dropped wakes.
 *
 * The limiter is best-effort: it serializes slot allocation under
 * a mutex and uses `delay()` to wait, which is cooperatively
 * cancellable. Tests inject a fake [nowMs] to verify the
 * rate-limiting math without sleeping.
 */
class BrokerConnectionLimiter internal constructor(
    private val minIntervalMs: Long,
    private val nowMs: () -> Long,
    private val delayFn: suspend (Long) -> Unit,
) {
    private val mutex = Mutex()
    private val lastOpenMs = mutableMapOf<String, Long>()

    /**
     * Wait until it's safe to open a WSS to [brokerUrl]. Suspends
     * for up to `minIntervalMs` if a recent connection was made.
     * Reserves a slot for the caller atomically — two concurrent
     * acquires get sequential slots without colliding.
     *
     * Cooperatively cancellable via the surrounding coroutine
     * (the underlying `delay()` propagates cancellation).
     */
    suspend fun acquire(brokerUrl: String) {
        val toWait = mutex.withLock {
            val now = nowMs()
            val last = lastOpenMs[brokerUrl]
            // Distinguish "never opened" (last == null) from "last
            // opened at time 0" — without this, the first acquire on
            // a low-clock test (nowMs starts < minIntervalMs) waits
            // unnecessarily. `null` means free; `Long` means slot
            // reserved at that timestamp.
            val waitMs = if (last == null) 0L
                         else (minIntervalMs - (now - last)).coerceAtLeast(0L)
            // Reserve the slot at "now + waitMs" so a concurrent
            // acquire computes its own delay against this reservation,
            // not against the last actual completion time.
            lastOpenMs[brokerUrl] = now + waitMs
            waitMs
        }
        if (toWait > 0) delayFn(toWait)
    }

    companion object {
        /** Cloudflare's threshold is 5+ conn/sec sustained. At
         * 1.5 s/connection that gives 40 conn/min — well within
         * the safe band but unobtrusive for hand-driven taps. */
        const val MIN_INTERVAL_MS = 1_500L

        /** Application-wide singleton. All WSS-open paths share
         * the same instance; per-broker-URL state lives inside. */
        val INSTANCE: BrokerConnectionLimiter by lazy {
            BrokerConnectionLimiter(
                minIntervalMs = MIN_INTERVAL_MS,
                nowMs = { System.currentTimeMillis() },
                delayFn = ::delay,
            )
        }
    }
}
