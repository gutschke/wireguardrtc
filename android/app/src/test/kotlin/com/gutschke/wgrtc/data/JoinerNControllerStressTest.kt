package com.gutschke.wgrtc.data

import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.RepeatedTest
import org.junit.jupiter.api.Test
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger

/**
 * Adversarial concurrency + failure-injection stress for
 * [JoinerNController]. Complements the happy-path coverage in
 * [JoinerNControllerTest] by hammering exactly the cases a real
 * user could inadvertently trigger.
 *
 * The fakes are deliberately laxer than the JoinerNControllerTest
 * fakes — they record call ordering and let tests inject delays
 * so the controller's `Mutex` serialisation is actually
 * observable.
 */
class JoinerNControllerStressTest {

    @Test
    fun `8 concurrent addJoiner calls all land in the active set`() = runBlocking<Unit> {
        val rig = newRig()
        coroutineScope {
            (0 until 8).map { idx ->
                async {
                    rig.controller.addJoiner(joiner("t$idx", addrOctet = idx + 1))
                }
            }.forEach { it.await() }
        }
        assertEquals((0 until 8).map { "t$it" }.toSet(),
            rig.controller.activeJoinerIds)
        // Every addJoiner triggered a rebuild — N stacks created.
        // After all 8 settle, exactly 8 stacks should have been
        // created (the first add creates one; each subsequent
        // tears down the previous and creates a new one).
        assertEquals(8, rig.fakeNative.stacksCreated)
        // Bridges opened: 1+2+3+4+5+6+7+8 = 36.
        assertEquals(36, rig.fakeNative.bridgesOpened)
    }

    @Test
    fun `addJoiner serializes — operations don't interleave inside rebuildLocked`() = runBlocking<Unit> {
        // Slow rebuild so concurrent addJoiner calls have time to
        // pile up at the Mutex. If serialisation is broken, the
        // ordering log would show interleaved {open, open, attach}
        // sequences instead of well-formed runs.
        val rig = newRig()
        rig.fakeNative.sharedStackNewDelayMs = 50
        coroutineScope {
            (0 until 4).map { idx ->
                async {
                    rig.controller.addJoiner(joiner("t$idx", addrOctet = idx + 1))
                }
            }.forEach { it.await() }
        }
        // Trace must alternate cleanly: each rebuild is a self-
        // contained run of {closeAll?, sharedStackNew, attach, openJoiner+}.
        val trace = rig.fakeNative.callLog.toList()
        // Confirm we never see two `sharedStackNew` calls without
        // a `sharedStackClose` between them. That would mean
        // operation 2 entered rebuildLocked while operation 1's
        // rebuild was still mid-flight.
        var openStacks = 0
        for (call in trace) {
            when (call) {
                "sharedStackNew" -> {
                    assertTrue(openStacks == 0,
                        "sharedStackNew while another stack open — trace=$trace")
                    openStacks = 1
                }
                "sharedStackClose" -> {
                    assertTrue(openStacks == 1, "close without open — trace=$trace")
                    openStacks = 0
                }
            }
        }
    }

    @Test
    fun `concurrent reconfigure during rebuild does not corrupt active set`() = runBlocking<Unit> {
        val rig = newRig()
        // Prime with one joiner.
        rig.controller.addJoiner(joiner("t1", addrOctet = 1, uapi = "v1"))
        rig.fakeNative.sharedStackNewDelayMs = 30
        coroutineScope {
            // Op A: trigger a rebuild via a second add.
            async {
                rig.controller.addJoiner(joiner("t2", addrOctet = 2))
            }
            // Op B + C: reconfigure t1 several times during the rebuild.
            // The Mutex inside JoinerNController serialises these
            // against the rebuild; without the lock, configureUapi
            // could race the per-id slot.
            async {
                repeat(3) { rig.controller.reconfigure("t1", "roam-$it") }
            }
        }
        assertEquals(setOf("t1", "t2"), rig.controller.activeJoinerIds)
        // Confirm no roam-call wrote to a bridge handle that had
        // already been closed by an in-flight rebuild — the fake
        // throws if that happens.
        assertFalse(rig.fakeNative.useAfterCloseObserved,
            "reconfigure landed on a closed bridge")
    }

    @Test
    fun `closeAll mid-add aborts cleanly`() = runBlocking<Unit> {
        val rig = newRig()
        rig.fakeNative.sharedStackNewDelayMs = 50
        // Stagger: start add, then immediately closeAll. The Mutex
        // makes one win. Either outcome is valid; the invariant is
        // that the controller ends in an internally consistent
        // state.
        coroutineScope {
            launch { rig.controller.addJoiner(joiner("t1", addrOctet = 1)) }
            launch { rig.controller.closeAll() }
        }
        // No partial state: either {} or {"t1"}. If add won, the
        // user's next action (a second add or removeJoiner) would
        // succeed. If closeAll won, the controller is empty.
        val ids = rig.controller.activeJoinerIds
        assertTrue(ids.isEmpty() || ids == setOf("t1"),
            "post-race state must be empty or singleton, got $ids")
        // Either way, no exception leaked from the addJoiner /
        // closeAll calls (the assertions before this would have
        // thrown).
    }

    @Test
    fun `rebuild failure on the second open leaves controller empty`() = runBlocking<Unit> {
        val rig = newRig()
        rig.controller.addJoiner(joiner("t1", addrOctet = 1))
        // Adding t2 triggers a rebuild that reopens t1 + tries
        // to open t2. The second openJoiner inside the rebuild
        // throws → controller catches → closeAll → clear active.
        rig.fakeNative.openJoinerFailNthRebuildSecondCall = true
        assertThrows(JoinerNException::class.java) {
            runBlocking {
                rig.controller.addJoiner(joiner("t2", addrOctet = 2))
            }
        }
        assertTrue(rig.controller.activeJoinerIds.isEmpty(),
            "controller must surrender both joiners after a mid-rebuild failure")
    }

    @Test
    fun `repeated full reset under concurrent ops produces no state leak`() = runBlocking<Unit> {
        val rig = newRig()
        // 5 rounds of: add 3 joiners concurrently, then closeAll.
        repeat(5) { round ->
            coroutineScope {
                (0 until 3).map { idx ->
                    async {
                        rig.controller.addJoiner(joiner("r${round}-$idx", addrOctet = idx + 1))
                    }
                }.forEach { it.await() }
            }
            rig.controller.closeAll()
            assertTrue(rig.controller.activeJoinerIds.isEmpty(),
                "round $round: closeAll should have emptied the set")
        }
        // Every stack we created must have been closed. (Tracks
        // resource-leak bugs that would manifest as stacksCreated
        // > stacksClosed in production.)
        assertEquals(
            rig.fakeNative.stacksCreated,
            rig.fakeNative.stacksClosed,
            "leaked stacks: created=${rig.fakeNative.stacksCreated} closed=${rig.fakeNative.stacksClosed}",
        )
    }

    @RepeatedTest(5)
    fun `concurrent remove of every active joiner ends in empty set`() = runBlocking<Unit> {
        // RepeatedTest catches order-dependent flakiness — if the
        // controller's mutex were broken, one of 5 runs would
        // produce a non-empty leftover.
        val rig = newRig()
        for (i in 0 until 5) {
            rig.controller.addJoiner(joiner("t$i", addrOctet = i + 1))
        }
        coroutineScope {
            (0 until 5).map { i ->
                async { rig.controller.removeJoiner("t$i") }
            }.forEach { it.await() }
        }
        assertTrue(rig.controller.activeJoinerIds.isEmpty(),
            "post-concurrent-remove state: ${rig.controller.activeJoinerIds}")
    }

    @Test
    fun `reconfigure on a non-existent id is a silent no-op`() = runBlocking<Unit> {
        val rig = newRig()
        rig.controller.addJoiner(joiner("t1", addrOctet = 1))
        // No throw, no state change.
        rig.controller.reconfigure("never-added", "anything")
        assertEquals(setOf("t1"), rig.controller.activeJoinerIds)
    }

    @Test
    fun `snapshotUapi after removeJoiner returns null`() = runBlocking<Unit> {
        val rig = newRig()
        rig.fakeNative.snapshotResult = "live"
        rig.controller.addJoiner(joiner("t1", addrOctet = 1))
        assertEquals("live", rig.controller.snapshotUapi("t1"))
        rig.controller.removeJoiner("t1")
        assertNull(rig.controller.snapshotUapi("t1"))
    }

    @Test
    fun `cancelled addJoiner caller does not leave the controller wedged`() = runBlocking<Unit> {
        // Real-user version of this: tap Connect, immediately
        // background the app — the Activity-scoped coroutine that
        // called addJoiner gets cancelled mid-rebuild. The
        // controller's Mutex must release; the NEXT addJoiner must
        // succeed.
        val rig = newRig()
        rig.fakeNative.sharedStackNewDelayMs = 200
        val first = launch {
            try {
                rig.controller.addJoiner(joiner("t1", addrOctet = 1))
            } catch (_: Throwable) { /* expected after cancel */ }
        }
        delay(30) // first add now suspended inside Mutex.withLock
        first.cancel()
        first.join()
        // Mutex must have been released; otherwise this add would
        // hang. The runBlocking will time out via the JUnit
        // timeout if so (we don't have a custom one set, so the
        // hang would surface as the test never finishing).
        rig.fakeNative.sharedStackNewDelayMs = 0
        rig.controller.addJoiner(joiner("t2", addrOctet = 2))
        assertEquals(setOf("t2"), rig.controller.activeJoinerIds)
    }

    @Test
    fun `addJoiner with empty addresses and empty routes does not throw`() = runBlocking<Unit> {
        // Edge case: a wg-quick config without any [Interface]
        // Address line or AllowedIPs would produce this. The
        // controller currently accepts it (the rebuild's union has
        // no addresses → Builder.establish would fail in
        // production, but the controller layer itself shouldn't
        // crash before reaching the backend).
        val rig = newRig()
        val emptyCfg = JoinerNController.JoinerConfig(
            tunnelId = "t1",
            addresses = emptyList(),
            routes = emptyList(),
            mtu = 1420,
            wgQuickUapi = "private_key=00\n",
        )
        // Our fake provider returns a positive fd regardless, so
        // this completes; we're verifying the controller doesn't
        // throw on the parse / dedupe step.
        rig.controller.addJoiner(emptyCfg)
        assertEquals(setOf("t1"), rig.controller.activeJoinerIds)
    }

    @Test
    fun `100 add-then-remove cycles produce no resource leak`() = runBlocking<Unit> {
        // Stress version of the rapid-cycle test in
        // JoinerNControllerTest. Catches off-by-one accumulation
        // bugs that small cycles miss.
        val rig = newRig()
        repeat(100) { i ->
            rig.controller.addJoiner(joiner("t-$i", addrOctet = (i % 250) + 1))
            rig.controller.removeJoiner("t-$i")
        }
        assertTrue(rig.controller.activeJoinerIds.isEmpty())
        // Stacks created == stacks closed.
        assertEquals(
            rig.fakeNative.stacksCreated,
            rig.fakeNative.stacksClosed,
        )
        // Bridges opened == bridges closed.
        assertEquals(
            rig.fakeNative.bridgesOpened,
            rig.fakeNative.bridgesClosed,
        )
    }

    @Test
    fun `addJoiner with identical config to existing slot is a no-op rebuild`() = runBlocking<Unit> {
        // Real user pattern: the same tunnel config gets pushed
        // twice because of a foreground-service restart firing
        // the ENROLL handler twice. Controller should treat it as
        // a replace (rebuild with the same union) and the active
        // set stays {"t1"}.
        val rig = newRig()
        val cfg = joiner("t1", addrOctet = 1)
        rig.controller.addJoiner(cfg)
        val stacksBefore = rig.fakeNative.stacksCreated
        rig.controller.addJoiner(cfg)
        assertEquals(setOf("t1"), rig.controller.activeJoinerIds)
        // A rebuild DID happen — replacement triggers it — but
        // the union is the same so the user-visible state matches.
        assertEquals(stacksBefore + 1, rig.fakeNative.stacksCreated)
    }

    // ── helpers ────────────────────────────────────────────────

    private data class Rig(
        val fakeNative: TraceFakeNative,
        val tunProvider: SimpleTunFdProvider,
        val controller: JoinerNController,
    )

    private fun newRig(): Rig {
        val fakeNative = TraceFakeNative()
        val backend = JoinerStackBackend(fakeNative)
        val tunProvider = SimpleTunFdProvider()
        return Rig(fakeNative, tunProvider, JoinerNController(backend, tunProvider))
    }

    private fun joiner(
        id: String,
        addrOctet: Int,
        mtu: Int = 1420,
        uapi: String = "private_key=00\n",
    ) = JoinerNController.JoinerConfig(
        tunnelId = id,
        addresses = listOf(Cidr("10.99.0.$addrOctet", 32)),
        routes = listOf(Cidr("10.99.0.0", 24)),
        mtu = mtu,
        wgQuickUapi = uapi,
    )

    private class SimpleTunFdProvider : TunFdProvider {
        private val nextFd = AtomicInteger(1000)
        override fun openTunFd(
            addresses: List<Cidr>,
            routes: List<Cidr>,
            mtu: Int,
            dnsServers: List<String>,
        ): Int = nextFd.incrementAndGet()
    }

    /**
     * Trace-recording fake — every API call appends to [callLog]
     * in arrival order. Tests can read the log to verify
     * serialisation invariants. Also tracks bridge handles so we
     * can detect use-after-close (which the production JNI would
     * crash on).
     */
    private class TraceFakeNative : JoinerStackNative {
        val callLog = ConcurrentLinkedQueue<String>()
        var stacksCreated = 0
        var stacksClosed = 0
        var bridgesOpened = 0
        var bridgesClosed = 0
        var sharedStackNewDelayMs: Long = 0
        var snapshotResult: String? = null
        var openJoinerFailNthRebuildSecondCall = false
        private var lastRebuildOpenCount = 0
        @Volatile var useAfterCloseObserved = false

        private val openStackHandles = mutableSetOf<Int>()
        private val openBridgeHandles = mutableSetOf<Int>()
        private val nextStackHandle = AtomicInteger(0)
        private val nextBridgeHandle = AtomicInteger(100)

        override fun sharedStackNew(mtu: Int): Int {
            callLog.add("sharedStackNew")
            if (sharedStackNewDelayMs > 0) {
                Thread.sleep(sharedStackNewDelayMs)
            }
            stacksCreated++
            lastRebuildOpenCount = 0
            val handle = nextStackHandle.incrementAndGet()
            synchronized(openStackHandles) { openStackHandles.add(handle) }
            return handle
        }

        override fun sharedStackClose(handle: Int) {
            callLog.add("sharedStackClose")
            stacksClosed++
            synchronized(openStackHandles) { openStackHandles.remove(handle) }
        }

        override fun sharedStackAttachKernelTun(handle: Int, fd: Int, mtu: Int): Int {
            callLog.add("sharedStackAttachKernelTun")
            return 0
        }

        override fun sharedStackOpenJoiner(
            stackHandle: Int,
            peerAllowedCsv: String?,
            interfaceAddrsCsv: String?,
            mtu: Int,
        ): Int {
            callLog.add("sharedStackOpenJoiner")
            lastRebuildOpenCount++
            if (openJoinerFailNthRebuildSecondCall && lastRebuildOpenCount == 2) {
                return -4
            }
            bridgesOpened++
            val handle = nextBridgeHandle.incrementAndGet()
            synchronized(openBridgeHandles) { openBridgeHandles.add(handle) }
            return handle
        }

        override fun configureUapi(bridgeHandle: Int, uapi: String): Int {
            callLog.add("configureUapi")
            synchronized(openBridgeHandles) {
                if (bridgeHandle !in openBridgeHandles) {
                    useAfterCloseObserved = true
                }
            }
            return 0
        }

        override fun snapshotUapi(bridgeHandle: Int): String? {
            return snapshotResult
        }

        override fun close(bridgeHandle: Int) {
            callLog.add("close")
            bridgesClosed++
            synchronized(openBridgeHandles) { openBridgeHandles.remove(bridgeHandle) }
        }
    }
}
