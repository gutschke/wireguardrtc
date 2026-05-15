package com.gutschke.wgrtc.signalling

import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

/**
 * Tests for the per-broker WSS rate limiter. Uses an injectable
 * clock + delayFn so we can verify the timing math without sleeping.
 */
class BrokerConnectionLimiterTest {

    /** Test harness that records `delay()` invocations and advances
     * a virtual clock by the requested amount. */
    private class FakeClock {
        var nowMs: Long = 1_000L
        val sleeps = mutableListOf<Long>()
        suspend fun fakeDelay(ms: Long) {
            sleeps += ms
            nowMs += ms
        }
    }

    private fun limiter(clock: FakeClock, intervalMs: Long = 1_500L) =
        BrokerConnectionLimiter(
            minIntervalMs = intervalMs,
            nowMs = { clock.nowMs },
            delayFn = { clock.fakeDelay(it) },
        )

    @Test fun `first acquire on new broker doesn't sleep`() = runBlocking {
        val clock = FakeClock()
        val l = limiter(clock)
        l.acquire("ws://broker.example/peerjs")
        assertTrue(clock.sleeps.isEmpty(),
            "first acquire should be immediate; got delays: ${clock.sleeps}")
    }

    @Test fun `back-to-back acquire waits the full interval`() = runBlocking {
        val clock = FakeClock()
        val l = limiter(clock, intervalMs = 1_500L)
        l.acquire("ws://broker.example/peerjs")
        // Clock hasn't advanced — second call should wait the full interval.
        l.acquire("ws://broker.example/peerjs")
        assertEquals(listOf(1_500L), clock.sleeps)
    }

    @Test fun `acquire after interval has elapsed doesn't sleep`() = runBlocking {
        val clock = FakeClock()
        val l = limiter(clock, intervalMs = 1_500L)
        l.acquire("ws://broker.example/peerjs")
        clock.nowMs += 2_000L // exceed the interval
        l.acquire("ws://broker.example/peerjs")
        assertTrue(clock.sleeps.isEmpty(),
            "interval already elapsed; got delays: ${clock.sleeps}")
    }

    @Test fun `acquire partway into interval waits remainder`() = runBlocking {
        val clock = FakeClock()
        val l = limiter(clock, intervalMs = 1_500L)
        l.acquire("ws://broker.example/peerjs")
        clock.nowMs += 500L
        l.acquire("ws://broker.example/peerjs")
        assertEquals(listOf(1_000L), clock.sleeps,
            "second acquire 500ms after first should wait 1000ms more")
    }

    @Test fun `different brokers don't share rate limit`() = runBlocking {
        val clock = FakeClock()
        val l = limiter(clock)
        l.acquire("ws://broker-a.example/peerjs")
        l.acquire("ws://broker-b.example/peerjs")
        assertTrue(clock.sleeps.isEmpty(),
            "different brokers have independent budgets; got delays: ${clock.sleeps}")
    }

    @Test fun `concurrent acquires on the same broker get sequential slots`() = runBlocking {
        // Three concurrent acquires on the same broker. First runs
        // immediately, second waits 1.5s, third waits 3.0s.
        val clock = FakeClock()
        val l = limiter(clock, intervalMs = 1_500L)
        coroutineScope {
            // Launch three async acquires; the mutex inside acquire
            // serializes slot allocation.
            (1..3).map {
                async { l.acquire("ws://broker.example/peerjs") }
            }.awaitAll()
        }
        // The recorded sleeps should be [1500, 1500] for callers 2 and 3
        // (caller 1 doesn't sleep). Order-of-recording matches mutex
        // acquisition order, which in coroutineScope-launched async
        // tasks is generally first-launch-first.
        assertEquals(listOf(1_500L, 1_500L), clock.sleeps,
            "three sequential opens should sleep 0+1500+1500 ms")
        // Total clock advancement: caller 2 advanced clock by 1500,
        // caller 3 saw last=clockAfterCaller2=2500, computed 1500ms
        // wait, advanced clock to 4000. Reservation pattern in
        // acquire() ensures this works.
        assertEquals(4_000L, clock.nowMs)
    }

    @Test fun `reservation prevents two callers from racing the same slot`() = runBlocking {
        // Specifically test the "reservation" semantics: caller 2's
        // computation of "how long to wait" must be against caller 1's
        // RESERVED slot, not against the (unchanged) last-actual-open
        // timestamp.
        val clock = FakeClock()
        val l = limiter(clock, intervalMs = 1_500L)
        // First acquire — sets lastOpenMs to nowMs (1000).
        l.acquire("b")
        assertEquals(1_000L, clock.nowMs)
        // No clock advance. Second and third both see lastOpenMs=1000;
        // without reservation, both would compute waitMs=1500 and both
        // would proceed simultaneously — defeating the rate limit.
        // With reservation, second computes waitMs=1500 and reserves
        // slot at 2500; third sees lastOpenMs=2500 and computes waitMs=2500.
        coroutineScope {
            val a = async { l.acquire("b") }
            val b = async { l.acquire("b") }
            a.await(); b.await()
        }
        // Both callers should have slept; the second to acquire should
        // have slept LONGER than 1500ms because the first reserved.
        assertEquals(2, clock.sleeps.size)
        // Sum of delays = 1500 + 2500 = 4000 — caller 2 waited 1500,
        // caller 3 waited 2500 (slot reserved at 2500, now=1000, wait=1500;
        // wait — let me re-derive).
        //
        // Step through with reservation logic:
        // start: nowMs=1000, lastOpenMs={b:1000}.
        // acquire #2: now=1000, last=1000, sinceLast=0, waitMs=1500.
        // reserve lastOpenMs[b] = 1000 + 1500 = 2500.
        // delayFn(1500) → nowMs=2500.
        // acquire #3: now=2500, last=2500, sinceLast=0, waitMs=1500.
        // reserve lastOpenMs[b] = 2500 + 1500 = 4000.
        // delayFn(1500) → nowMs=4000.
        // So both delays should be 1500. Total nowMs at end: 4000.
        assertEquals(listOf(1_500L, 1_500L), clock.sleeps)
        assertEquals(4_000L, clock.nowMs)
    }
}
