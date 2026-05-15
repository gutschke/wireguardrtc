@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package com.gutschke.wgrtc.data

import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Pinning the merge semantics that back [WgrtcViewModel.activeTunnelIds]:
 * the unified set is the joiner id (if any) ∪ host ids.  All four
 * corners — neither / joiner-only / host-only / both — produce the
 * expected union.  The host side is a `Set<String>` since D4.H1
 * because the app now runs N concurrent host tunnels.
 */
class ActiveTunnelTrackerTest {

    @Test
    fun `union with no joiner is just the host set`() {
        assertEquals(emptySet<String>(), ActiveTunnelTracker.union(null, emptySet()))
        assertEquals(setOf("h1", "h2"),
            ActiveTunnelTracker.union(null, setOf("h1", "h2")))
    }

    @Test
    fun `union with joiner only returns singleton of joiner`() {
        assertEquals(setOf("j1"), ActiveTunnelTracker.union("j1", emptySet()))
    }

    @Test
    fun `union with both adds joiner to the host set`() {
        assertEquals(setOf("h1", "h2", "j1"),
            ActiveTunnelTracker.union("j1", setOf("h1", "h2")))
    }

    @Test
    fun `union dedupes if joiner id is also somehow in the host set`() {
        // Defensive: shouldn't happen at runtime (the two slot groups
        // are independent), but the helper must not produce a
        // duplicate entry in any shape.
        assertEquals(setOf("x"),
            ActiveTunnelTracker.union("x", setOf("x")))
    }

    @Test
    fun `combinedFlow reflects host-set updates`() = runTest {
        val joiner = MutableStateFlow<String?>(null)
        val host = MutableStateFlow<Set<String>>(emptySet())
        val emissions = mutableListOf<Set<String>>()
        val job = launch {
            ActiveTunnelTracker.combinedFlow(joiner, host).collect { emissions += it }
        }
        runCurrent()
        host.value = setOf("h1")
        runCurrent()
        host.value = setOf("h1", "h2")
        runCurrent()
        job.cancel()
        assertEquals(
            listOf(emptySet(), setOf("h1"), setOf("h1", "h2")),
            emissions,
        )
    }

    @Test
    fun `combinedFlow reflects joiner updates without losing host set`() = runTest {
        val joiner = MutableStateFlow<String?>(null)
        val host = MutableStateFlow<Set<String>>(setOf("h1"))
        val emissions = mutableListOf<Set<String>>()
        val job = launch {
            ActiveTunnelTracker.combinedFlow(joiner, host).collect { emissions += it }
        }
        runCurrent()
        joiner.value = "j1"
        runCurrent()
        joiner.value = null
        runCurrent()
        job.cancel()
        assertEquals(
            listOf(setOf("h1"), setOf("h1", "j1"), setOf("h1")),
            emissions,
        )
    }

    @Test
    fun `isActiveFlow tracks both slot groups`() = runTest {
        val joiner = MutableStateFlow<String?>(null)
        val host = MutableStateFlow<Set<String>>(emptySet())
        val flow = ActiveTunnelTracker.isActiveFlow("target", joiner, host)
        assertFalse(flow.first())
        host.value = setOf("target")
        assertTrue(flow.first())
        host.value = emptySet()
        assertFalse(flow.first())
        joiner.value = "target"
        assertTrue(flow.first())
    }

    @Test
    fun `isActiveFlow ignores unrelated ids`() = runTest {
        val joiner = MutableStateFlow<String?>("other-joiner")
        val host = MutableStateFlow<Set<String>>(setOf("other-host"))
        val flow = ActiveTunnelTracker.isActiveFlow("target", joiner, host)
        assertFalse(flow.first())
    }

    // ─── D4.H2: per-tunnel-cache leak fix ─────────────────────────
    //
    // The fix has two parts living in WgrtcViewModel:
    //   1. Per-id cache StateFlows use SharingStarted.WhileSubscribed
    //      (5 s grace) instead of Eagerly, so an unsubscribed tunnel
    //      doesn't keep a permanent upstream collector rooted in
    //      viewModelScope.
    //   2. deleteTunnel() / pruneTunnelCaches() evicts the entry from
    //      the three ConcurrentHashMap caches so a long-lived process
    //      with many rename/delete cycles can't grow the maps
    //      unboundedly.
    //
    // Both behaviours are testable here against the same primitives
    // the ViewModel uses (combinedFlow + stateIn + a HashMap cache),
    // without dragging in WgrtcApp / Application Context.
    //
    // D4.H5: the ViewModel-level integration assertion
    // ("disconnectAll closes joiner + teardownAll host slots", and
    // the full Compose-subscriber lifecycle) needs an instrumented
    // test rig with HostModeBackend mocked.  The unit-test layer
    // here pins the underlying flow contract; the instrumented
    // layer will exercise the wiring.

    @Test
    fun `WhileSubscribed sharing stops collecting upstream when no subscribers remain`() = runTest {
        // stateIn launches a long-lived coroutine in the scope we
        // pass.  runTest's `backgroundScope` is the right place
        // for it — the test runtime auto-cancels backgroundScope
        // on completion, so the test doesn't hang waiting for the
        // sharing coroutine to terminate.  Mirrors the lifetime
        // viewModelScope provides in production.
        val joiner = MutableStateFlow<String?>(null)
        val host = MutableStateFlow<Set<String>>(emptySet())
        // Build the same kind of cached per-id flow
        // WgrtcViewModel constructs in isActive(id) —
        // combinedFlow → distinct → map →
        // stateIn(WhileSubscribed(5_000)).
        val shared = ActiveTunnelTracker.combinedFlow(joiner, host)
            .map { it.contains("target") }
            .distinctUntilChanged()
            .stateIn(
                backgroundScope,
                SharingStarted.WhileSubscribed(5_000),
                false,
            )
        // No subscribers yet.  Subscription-tracking is
        // exposed via subscriptionCount on the upstream
        // MutableStateFlow, which is what we assert against.
        val collector = backgroundScope.launch { shared.collect { /* noop */ } }
        runCurrent()
        assertEquals(1, host.subscriptionCount.value,
            "WhileSubscribed should attach an upstream subscriber once we collect")
        collector.cancel()
        runCurrent()
        // Within the 5 s grace window the upstream stays
        // subscribed so a rapid screen-swap (TunnelDetail →
        // TunnelList → back) doesn't tear down + rebuild the
        // combine() pipeline.
        assertEquals(1, host.subscriptionCount.value,
            "subscriber count should still be 1 inside the grace window")
        // After 5 s, the upstream subscription drops.
        advanceTimeBy(5_500)
        runCurrent()
        assertEquals(0, host.subscriptionCount.value,
            "WhileSubscribed grace window must drop the upstream once no one is collecting")
    }

    @Test
    fun `cached per-tunnel flow is evicted on delete`() = runTest {
        // Mirror the cache shape in WgrtcViewModel — a single
        // ConcurrentHashMap mapping tunnelId → per-id
        // StateFlow.  pruneTunnelCaches() must reliably drop
        // the entry so long-lived processes don't grow the
        // map.
        val cache = ConcurrentHashMap<String, StateFlow<Boolean>>()
        val joiner = MutableStateFlow<String?>(null)
        val host = MutableStateFlow<Set<String>>(setOf("t-1", "t-2"))

        fun perIdFlow(id: String): StateFlow<Boolean> = cache.getOrPut(id) {
            ActiveTunnelTracker.isActiveFlow(id, joiner, host)
                .stateIn(backgroundScope, SharingStarted.WhileSubscribed(5_000), false)
        }

        // Two callers ask for two ids; cache fills.
        perIdFlow("t-1")
        perIdFlow("t-2")
        assertNotNull(cache["t-1"])
        assertNotNull(cache["t-2"])
        assertEquals(2, cache.size)

        val firstT1 = cache["t-1"]
        // Simulate WgrtcViewModel.pruneTunnelCaches("t-1")
        // after deleteTunnel("t-1"): the entry is gone and
        // the cache map collapses to one element.  A
        // subsequent lookup builds a FRESH StateFlow for
        // "t-1" — not the previously-cached one.
        cache.remove("t-1")
        assertNull(cache["t-1"])
        assertEquals(1, cache.size)

        val rebuilt = perIdFlow("t-1")
        assertNotNull(rebuilt)
        assertEquals(2, cache.size)
        // The rebuilt flow is a distinct object from the one
        // that was evicted — the leak is gone and the new
        // entry is what subsequent subscribers would hit.
        assertTrue(cache["t-1"] === rebuilt,
            "After eviction the cache hands out the freshly-built flow")
        assertFalse(rebuilt === firstT1,
            "The post-eviction lookup must produce a NEW flow, not resurrect the cached one")
    }
}
