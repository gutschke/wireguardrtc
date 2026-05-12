package com.gutschke.wgrtc.data

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.IOException
import java.net.InetSocketAddress
import java.util.Base64
import java.util.concurrent.atomic.AtomicInteger

class HostModeRunnerTest {

    private val parentJob = SupervisorJob()
    private val parentScope = CoroutineScope(Dispatchers.Default + parentJob)

    @AfterEach fun tearDown() { parentJob.cancel() }

    private val privKey32 = ByteArray(32) { (it + 1).toByte() }
    private val privB64 = Base64.getEncoder().encodeToString(privKey32)
    private val peer1Key = ByteArray(32) { (0xaa).toByte() }
    private val peer1B64 = Base64.getEncoder().encodeToString(peer1Key)

    private fun config(
        tcpPorts: List<Int> = listOf(80),
        udpPorts: List<Int> = listOf(53),
    ) = HostModeRunnerConfig(
        localAddr = "10.99.0.1",
        listenPort = 51820,
        mtu = 1420,
        privateKeyB64 = privB64,
        peers = listOf(HostModeUapi.Peer(peer1B64, "10.99.0.2/32")),
        tcpPorts = tcpPorts,
        udpPorts = udpPorts,
        targetResolver = { _, _ -> InetSocketAddress("9.9.9.9", 80) },
    )

    @Test
    fun `start opens backend with localAddr+mtu+listenPort and applies UAPI`() {
        val backend = HookedBackend()
        val factory = HookedFactory(backend)
        val runner = HostModeRunner(factory, parentScope)
        runner.start(config())
        assertEquals(listOf(Triple("10.99.0.1", 1420, 51820)), factory.opens)
        // UAPI string contains private_key= and listen_port= and the
        // peer's allowed_ip= line.
        val uapi = backend.uapiCalls.single()
        assertTrue(uapi.contains("private_key="))
        assertTrue(uapi.contains("listen_port=51820"))
        assertTrue(uapi.contains("allowed_ip=10.99.0.2/32"))
    }

    @Test
    fun `start registers TCP and UDP listeners on the configured ports`() {
        val backend = HookedBackend()
        val runner = HostModeRunner(HookedFactory(backend), parentScope)
        runner.start(config(tcpPorts = listOf(80, 443), udpPorts = listOf(53, 1194)))
        assertEquals(listOf(80, 443), backend.tcpPorts)
        assertEquals(listOf(53, 1194), backend.udpPorts)
    }

    @Test
    fun `setProtector forwards to endpoint after start`() {
        val backend = HookedBackend()
        val runner = HostModeRunner(HookedFactory(backend), parentScope)
        runner.start(config())
        val protector = WgFdProtector { fd -> fd > 0 }
        runner.setProtector(protector)
        assertEquals(listOf<WgFdProtector?>(protector), backend.protectors)
    }

    @Test
    fun `setProtector before start is a no-op`() {
        val backend = HookedBackend()
        val runner = HostModeRunner(HookedFactory(backend), parentScope)
        runner.setProtector(WgFdProtector { false })
        // Backend was never opened.
        assertEquals(0, backend.protectors.size)
    }

    @Test
    fun `stop closes endpoint and is idempotent`() {
        val backend = HookedBackend()
        val runner = HostModeRunner(HookedFactory(backend), parentScope)
        runner.start(config())
        runner.stop()
        runner.stop()
        runner.stop()
        assertEquals(1, backend.closeCount.get())
        assertFalse(runner.isRunning)
    }

    @Test
    fun `start a second time throws`() {
        val backend = HookedBackend()
        val runner = HostModeRunner(HookedFactory(backend), parentScope)
        runner.start(config())
        assertThrows(IllegalStateException::class.java) {
            runner.start(config())
        }
    }

    @Test
    fun `start failure cleans up the backend`() {
        // Backend whose configureUapi throws — the runner should
        // close the freshly-opened backend so we don't leak the
        // userspace WG device.
        val backend = HookedBackend(uapiError = IOException("bad config"))
        val factory = HookedFactory(backend)
        val runner = HostModeRunner(factory, parentScope)
        assertThrows(IOException::class.java) { runner.start(config()) }
        assertEquals(1, backend.closeCount.get())
        assertFalse(runner.isRunning)
    }

    @Test
    fun `setProtector after stop is a no-op`() {
        val backend = HookedBackend()
        val runner = HostModeRunner(HookedFactory(backend), parentScope)
        runner.start(config())
        runner.stop()
        runner.setProtector(WgFdProtector { false })
        // Endpoint was already closed when stop ran; backend's
        // post-close setProtector calls are silently dropped.
        assertEquals(0, backend.protectors.size)
    }

    @Test
    fun `isRunning reflects start and stop`() {
        val backend = HookedBackend()
        val runner = HostModeRunner(HookedFactory(backend), parentScope)
        assertFalse(runner.isRunning)
        runner.start(config())
        assertTrue(runner.isRunning)
        runner.stop()
        assertFalse(runner.isRunning)
    }

    @Test
    fun `runner supports zero TCP and UDP listen ports`() {
        // Edge case: a host that doesn't expose any listen ports
        // (maybe future Cascade mode) — just configures and waits.
        val backend = HookedBackend()
        val runner = HostModeRunner(HookedFactory(backend), parentScope)
        runner.start(config(tcpPorts = emptyList(), udpPorts = emptyList()))
        assertEquals(0, backend.tcpPorts.size)
        assertEquals(0, backend.udpPorts.size)
        assertNotNull(backend.uapiCalls.firstOrNull())
    }

    @Test
    fun `reconfigureUapi pushes a fresh string without re-opening the backend`() {
        val backend = HookedBackend()
        val runner = HostModeRunner(HookedFactory(backend), parentScope)
        runner.start(config())
        val initialUapi = backend.uapiCalls.single()
        val reconfigured = "private_key=zz\nlisten_port=51820\npublic_key=aa\nallowed_ip=10.99.0.5/32\n"
        runner.reconfigureUapi(reconfigured)
        assertEquals(2, backend.uapiCalls.size)
        assertEquals(reconfigured, backend.uapiCalls[1])
        assertEquals(0, backend.closeCount.get())
        // Sanity: the initial UAPI is unchanged.
        assertEquals(initialUapi, backend.uapiCalls[0])
    }

    @Test
    fun `reconfigureUapi before start throws`() {
        val backend = HookedBackend()
        val runner = HostModeRunner(HookedFactory(backend), parentScope)
        assertThrows(IllegalStateException::class.java) {
            runner.reconfigureUapi("private_key=00\nlisten_port=51820\n")
        }
    }

    @Test
    fun `reconfigureUapi after stop throws`() {
        val backend = HookedBackend()
        val runner = HostModeRunner(HookedFactory(backend), parentScope)
        runner.start(config())
        runner.stop()
        assertThrows(IllegalStateException::class.java) {
            runner.reconfigureUapi("private_key=00\nlisten_port=51820\n")
        }
    }

    @Test
    fun `pause issues a no-peers ephemeral-listen UAPI without closing the backend`() {
        val backend = HookedBackend()
        val runner = HostModeRunner(HookedFactory(backend), parentScope)
        runner.start(config())
        runner.pause()
        // Pause must keep the backend alive so resume() can reconfigure
        // it without re-opening ('s wireguard-go close+reopen
        // panics with "bulkBarrierPreWrite" —).
        assertEquals(0, backend.closeCount.get())
        // The pause UAPI should clear all peers + drop the listen port.
        // The exact format is dictated by wireguard-go's IpcSet.
        val pauseUapi = backend.uapiCalls.last()
        assertTrue(pauseUapi.contains("replace_peers=true"),
            "pause UAPI should include replace_peers=true to drop the peer table")
        assertTrue(pauseUapi.contains("listen_port=0"),
            "pause UAPI should set listen_port=0 (ephemeral) so peers can't reach the original port")
    }

    @Test
    fun `pause then reconfigureUapi resumes the bridge with the new config`() {
        val backend = HookedBackend()
        val runner = HostModeRunner(HookedFactory(backend), parentScope)
        runner.start(config())
        runner.pause()
        val resumeUapi =
            "private_key=ff\nlisten_port=51820\npublic_key=aa\nallowed_ip=10.99.0.5/32\n"
        runner.reconfigureUapi(resumeUapi)
        // After pause+resume the runner must still be in the running
        // state (so a future stop is allowed and does the right thing).
        assertTrue(runner.isRunning)
        // The most recent UAPI was the resume payload.
        assertEquals(resumeUapi, backend.uapiCalls.last())
    }

    @Test
    fun `pause is idempotent`() {
        val backend = HookedBackend()
        val runner = HostModeRunner(HookedFactory(backend), parentScope)
        runner.start(config())
        runner.pause()
        runner.pause()
        runner.pause()
        assertEquals(0, backend.closeCount.get())
    }

    @Test
    fun `pause before start throws`() {
        val backend = HookedBackend()
        val runner = HostModeRunner(HookedFactory(backend), parentScope)
        assertThrows(IllegalStateException::class.java) { runner.pause() }
    }

    @Test
    fun `pause after stop throws`() {
        val backend = HookedBackend()
        val runner = HostModeRunner(HookedFactory(backend), parentScope)
        runner.start(config())
        runner.stop()
        assertThrows(IllegalStateException::class.java) { runner.pause() }
    }

    @Test
    fun `targetResolver argument is propagated into endpoint`() = runBlocking<Unit> {
        // Indirect test: trigger an accept on the fake backend and
        // confirm the resolver lambda we passed in is the one the
        // listener consults. We cheat by capturing the resolver
        // reference exposed by the backend's last listenTcp call.
        val backend = HookedBackend()
        val seen = AtomicInteger(0)
        val resolver = { _: String, _: String ->
            seen.incrementAndGet()
            null // refuse the connection so we don't actually run a forwarder.
        }
        val runner = HostModeRunner(HookedFactory(backend), parentScope)
        runner.start(config(tcpPorts = listOf(80)).copy(targetResolver = resolver))
        backend.fireTcpAccept("10.99.0.2:1", "10.99.0.1:80",
            object : WgTcpHandle {
                override val peerAddress = "10.99.0.2:1"
                override val listenAddress = "10.99.0.1:80"
                override fun read(buf: ByteArray): Int = -1
                override fun write(buf: ByteArray) {}
                override fun close() {}
            })
        assertEquals(1, seen.get())
    }

    /** Backend fake — captures everything so tests can assert. */
    private class HookedBackend(
        private val uapiError: Exception? = null,
    ) : WgBridgeBackend {
        val uapiCalls = mutableListOf<String>()
        val tcpPorts = mutableListOf<Int>()
        val udpPorts = mutableListOf<Int>()
        val protectors = mutableListOf<WgFdProtector?>()
        val closeCount = AtomicInteger(0)
        @Volatile private var lastTcpAcceptor: WgTcpAcceptor? = null
        @Volatile private var closedFlag = false

        fun fireTcpAccept(peer: String, listen: String, handle: WgTcpHandle) {
            (lastTcpAcceptor ?: error("no acceptor registered"))
                .onAccept(peer, listen, handle)
        }

        override fun configureUapi(uapi: String) {
            uapiError?.let { throw it }
            uapiCalls += uapi
        }
        override fun listenTcp(port: Int, acceptor: WgTcpAcceptor) {
            tcpPorts += port
            lastTcpAcceptor = acceptor
        }
        override fun listenUdp(port: Int, receiver: WgUdpReceiver): WgUdpSink {
            udpPorts += port
            return object : WgUdpSink {
                override fun sendTo(peerAddr: String, data: ByteArray) {}
                override fun close() {}
            }
        }
        override fun setFdProtector(protector: WgFdProtector?) {
            // Match RealWgBridgeBackend's behaviour: silently ignore
            // calls after close so the runner's setProtector-after-stop
            // doesn't surface the post-close state to assertions.
            if (closedFlag) return
            protectors += protector
        }
        override fun close() {
            if (closedFlag) return
            closedFlag = true
            closeCount.incrementAndGet()
        }
    }

    /** Factory fake — records every open() request. */
    private class HookedFactory(private val backend: WgBridgeBackend) : WgBridgeBackendFactory {
        val opens = mutableListOf<Triple<String, Int, Int>>()
        override fun open(localAddr: String, mtu: Int, listenPort: Int): WgBridgeBackend {
            opens += Triple(localAddr, mtu, listenPort)
            return backend
        }
    }
}
