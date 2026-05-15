package com.gutschke.wgrtc.data

import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicInteger

/**
 * D4.J3 unit tests for [JoinerStackBackend].  Use an in-process
 * fake [JoinerStackNative] so we exercise the slot map / lifecycle
 * /  flow plumbing without touching the .so.  The JNI surface
 * itself was already validated end-to-end by the Go tests in
 * `wgbridge_native/`; this file's job is the Kotlin-side state
 * machine.
 */
class JoinerStackBackendTest {

    // ── tests ──────────────────────────────────────────────────

    @Test
    fun `bindKernelTun creates a stack and reports kernelTunBound`() = runBlocking<Unit> {
        val fake = FakeJoinerStackNative()
        val be = JoinerStackBackend(fake)
        assertFalse(be.kernelTunBound)
        be.bindKernelTun(fd = 42, mtu = 1420)
        assertTrue(be.kernelTunBound)
        assertEquals(1, fake.stacksCreated)
        assertEquals(1, fake.kernelTunAttachCount)
        assertEquals(42, fake.lastAttachedFd)
        assertEquals(1420, fake.lastAttachedMtu)
    }

    @Test
    fun `bindKernelTun twice without closeAll throws`() = runBlocking<Unit> {
        val be = JoinerStackBackend(FakeJoinerStackNative())
        be.bindKernelTun(fd = 1, mtu = 1420)
        assertThrows(IllegalStateException::class.java) {
            runBlocking { be.bindKernelTun(fd = 2, mtu = 1420) }
        }
    }

    @Test
    fun `bindKernelTun failure rolls back the stack`() = runBlocking<Unit> {
        val fake = FakeJoinerStackNative().apply {
            attachKernelTunResult = -2 // simulate failure
        }
        val be = JoinerStackBackend(fake)
        assertThrows(JoinerStackException::class.java) {
            runBlocking { be.bindKernelTun(fd = 7, mtu = 1420) }
        }
        // Stack should have been closed.
        assertFalse(be.kernelTunBound)
        assertEquals(1, fake.stacksClosed,
            "failed bind must close the just-created stack so we don't leak handles")
    }

    @Test
    fun `openJoiner without bindKernelTun throws`() = runBlocking<Unit> {
        val be = JoinerStackBackend(FakeJoinerStackNative())
        assertThrows(JoinerStackException::class.java) {
            runBlocking {
                be.openJoiner("t1",
                    peerAllowed = listOf("10.0.0.0/24"),
                    interfaceAddrs = listOf("10.0.0.2/32"),
                    mtu = 1420,
                    wgQuickUapi = "private_key=\n")
            }
        }
    }

    @Test
    fun `openJoiner happy path registers slot and exposes activeJoinerIds`() = runBlocking<Unit> {
        val fake = FakeJoinerStackNative()
        val be = JoinerStackBackend(fake)
        be.bindKernelTun(fd = 42, mtu = 1420)
        val handle = be.openJoiner(
            "t1",
            peerAllowed = listOf("10.99.0.0/24"),
            interfaceAddrs = listOf("10.99.0.2/32"),
            mtu = 1420,
            wgQuickUapi = "private_key=00\n",
        )
        assertTrue(handle > 0)
        assertEquals(setOf("t1"), be.activeJoinerIds.value)
        // Fake captured the CSV-joined inputs.
        assertEquals("10.99.0.0/24", fake.lastOpenJoinerPeerAllowedCsv)
        assertEquals("10.99.0.2/32", fake.lastOpenJoinerInterfaceAddrsCsv)
        // UAPI was applied to the returned bridge handle.
        assertEquals(handle, fake.lastConfigureUapiHandle)
        assertEquals("private_key=00\n", fake.lastConfigureUapi)
    }

    @Test
    fun `openJoiner UAPI failure closes the bridge so no orphan slot`() = runBlocking<Unit> {
        val fake = FakeJoinerStackNative().apply { configureUapiResult = -2 }
        val be = JoinerStackBackend(fake)
        be.bindKernelTun(fd = 1, mtu = 1420)
        assertThrows(JoinerStackException::class.java) {
            runBlocking {
                be.openJoiner("t1",
                    peerAllowed = emptyList(),
                    interfaceAddrs = emptyList(),
                    mtu = 1420,
                    wgQuickUapi = "bad\n")
            }
        }
        assertTrue(be.activeJoinerIds.value.isEmpty())
        // Bridge was opened, then closed by the failure recovery.
        assertEquals(1, fake.bridgesOpened)
        assertEquals(1, fake.bridgesClosed,
            "failed openJoiner must close the bridge — leaked handles would " +
            "stack up over reconfigure cycles")
    }

    @Test
    fun `openJoiner with same tunnelId twice throws`() = runBlocking<Unit> {
        val be = JoinerStackBackend(FakeJoinerStackNative())
        be.bindKernelTun(fd = 1, mtu = 1420)
        be.openJoiner("t1", emptyList(), emptyList(), 1420, "u\n")
        assertThrows(JoinerStackException::class.java) {
            runBlocking { be.openJoiner("t1", emptyList(), emptyList(), 1420, "u\n") }
        }
    }

    @Test
    fun `empty peerAllowed and interfaceAddrs map to null csv`() = runBlocking<Unit> {
        val fake = FakeJoinerStackNative()
        val be = JoinerStackBackend(fake)
        be.bindKernelTun(fd = 1, mtu = 1420)
        be.openJoiner("t1",
            peerAllowed = emptyList(),
            interfaceAddrs = emptyList(),
            mtu = 1420,
            wgQuickUapi = "u\n",
        )
        // Null lets the JNI layer pass through without an empty
        // string that the Go parser would still iterate.
        assertNull(fake.lastOpenJoinerPeerAllowedCsv)
        assertNull(fake.lastOpenJoinerInterfaceAddrsCsv)
    }

    @Test
    fun `reconfigure issues a fresh UAPI`() = runBlocking<Unit> {
        val fake = FakeJoinerStackNative()
        val be = JoinerStackBackend(fake)
        be.bindKernelTun(fd = 1, mtu = 1420)
        be.openJoiner("t1", emptyList(), emptyList(), 1420, "initial\n")
        be.reconfigure("t1", "updated\n")
        assertEquals("updated\n", fake.lastConfigureUapi)
        assertEquals(2, fake.configureUapiCount)
    }

    @Test
    fun `reconfigure on missing tunnelId is silent no-op`() = runBlocking<Unit> {
        val fake = FakeJoinerStackNative()
        val be = JoinerStackBackend(fake)
        be.bindKernelTun(fd = 1, mtu = 1420)
        be.reconfigure("never-opened", "u\n")
        // No-op: no UAPI call beyond the initial open path (none here).
        assertEquals(0, fake.configureUapiCount)
    }

    @Test
    fun `snapshotUapi returns fakes value for known handle`() = runBlocking<Unit> {
        val fake = FakeJoinerStackNative().apply { snapshotResult = "dump-bytes" }
        val be = JoinerStackBackend(fake)
        be.bindKernelTun(fd = 1, mtu = 1420)
        be.openJoiner("t1", emptyList(), emptyList(), 1420, "u\n")
        assertEquals("dump-bytes", be.snapshotUapi("t1"))
    }

    @Test
    fun `snapshotUapi returns null for unknown id`() {
        val be = JoinerStackBackend(FakeJoinerStackNative())
        assertNull(be.snapshotUapi("never-opened"))
    }

    @Test
    fun `closeJoiner removes the slot and closes the bridge`() = runBlocking<Unit> {
        val fake = FakeJoinerStackNative()
        val be = JoinerStackBackend(fake)
        be.bindKernelTun(fd = 1, mtu = 1420)
        be.openJoiner("t1", emptyList(), emptyList(), 1420, "u\n")
        be.openJoiner("t2", emptyList(), emptyList(), 1420, "u\n")
        be.closeJoiner("t1")
        assertEquals(setOf("t2"), be.activeJoinerIds.value)
        assertEquals(1, fake.bridgesClosed)
    }

    @Test
    fun `closeJoiner is idempotent for unknown id`() = runBlocking<Unit> {
        val be = JoinerStackBackend(FakeJoinerStackNative())
        be.bindKernelTun(fd = 1, mtu = 1420)
        // Doesn't throw — no slot for that id.
        be.closeJoiner("never-opened")
    }

    @Test
    fun `closeAll tears down every joiner then the stack`() = runBlocking<Unit> {
        val fake = FakeJoinerStackNative()
        val be = JoinerStackBackend(fake)
        be.bindKernelTun(fd = 1, mtu = 1420)
        be.openJoiner("t1", emptyList(), emptyList(), 1420, "u\n")
        be.openJoiner("t2", emptyList(), emptyList(), 1420, "u\n")
        assertEquals(setOf("t1", "t2"), be.activeJoinerIds.value)

        be.closeAll()
        assertTrue(be.activeJoinerIds.value.isEmpty())
        assertFalse(be.kernelTunBound)
        assertEquals(2, fake.bridgesClosed,
            "every joiner must be closed before the stack itself is destroyed")
        assertEquals(1, fake.stacksClosed)
    }

    @Test
    fun `closeAll on a fresh backend is a no-op`() = runBlocking<Unit> {
        val fake = FakeJoinerStackNative()
        val be = JoinerStackBackend(fake)
        be.closeAll()
        assertEquals(0, fake.stacksClosed)
    }

    @Test
    fun `closeAll is idempotent`() = runBlocking<Unit> {
        val fake = FakeJoinerStackNative()
        val be = JoinerStackBackend(fake)
        be.bindKernelTun(fd = 1, mtu = 1420)
        be.closeAll()
        // Second closeAll is harmless — no extra stack close, no
        // exceptions.
        be.closeAll()
        assertEquals(1, fake.stacksClosed)
    }

    @Test
    fun `activeJoinerIds flow emits transitions`() = runBlocking<Unit> {
        val be = JoinerStackBackend(FakeJoinerStackNative())
        be.bindKernelTun(fd = 1, mtu = 1420)
        // Initial empty.
        assertEquals(emptySet<String>(), be.activeJoinerIds.value)
        be.openJoiner("a", emptyList(), emptyList(), 1420, "u\n")
        be.activeJoinerIds.first { it == setOf("a") }
        be.openJoiner("b", emptyList(), emptyList(), 1420, "u\n")
        be.activeJoinerIds.first { it == setOf("a", "b") }
        be.closeJoiner("a")
        be.activeJoinerIds.first { it == setOf("b") }
        be.closeAll()
        be.activeJoinerIds.first { it.isEmpty() }
    }

    /**
     * In-process fake of [JoinerStackNative].  Hands out
     * monotonic handles starting at 1 (matches the production
     * convention: positive=success, 0=invalid).  Each method
     * records call counts + last arguments so tests can assert
     * on the JNI-side conversation without mocks.
     */
    private class FakeJoinerStackNative : JoinerStackNative {
        private val nextStackHandle = AtomicInteger(0)
        private val nextBridgeHandle = AtomicInteger(100)

        var stacksCreated = 0
        var stacksClosed = 0
        var kernelTunAttachCount = 0
        var lastAttachedFd: Int = 0
        var lastAttachedMtu: Int = 0
        var attachKernelTunResult: Int = 0 // 0 = success

        var bridgesOpened = 0
        var bridgesClosed = 0
        var lastOpenJoinerPeerAllowedCsv: String? = null
        var lastOpenJoinerInterfaceAddrsCsv: String? = null

        var configureUapiCount = 0
        var lastConfigureUapiHandle: Int = 0
        var lastConfigureUapi: String = ""
        var configureUapiResult: Int = 0 // 0 = success

        var snapshotResult: String? = null

        override fun sharedStackNew(mtu: Int): Int {
            stacksCreated++
            return nextStackHandle.incrementAndGet()
        }

        override fun sharedStackClose(handle: Int) {
            stacksClosed++
        }

        override fun sharedStackAttachKernelTun(handle: Int, fd: Int, mtu: Int): Int {
            kernelTunAttachCount++
            lastAttachedFd = fd
            lastAttachedMtu = mtu
            return attachKernelTunResult
        }

        override fun sharedStackOpenJoiner(
            stackHandle: Int,
            peerAllowedCsv: String?,
            interfaceAddrsCsv: String?,
            mtu: Int,
        ): Int {
            bridgesOpened++
            lastOpenJoinerPeerAllowedCsv = peerAllowedCsv
            lastOpenJoinerInterfaceAddrsCsv = interfaceAddrsCsv
            return nextBridgeHandle.incrementAndGet()
        }

        override fun configureUapi(bridgeHandle: Int, uapi: String): Int {
            configureUapiCount++
            lastConfigureUapiHandle = bridgeHandle
            lastConfigureUapi = uapi
            return configureUapiResult
        }

        override fun snapshotUapi(bridgeHandle: Int): String? = snapshotResult

        override fun close(bridgeHandle: Int) {
            bridgesClosed++
        }
    }
}
