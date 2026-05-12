package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.IOException
import java.util.concurrent.atomic.AtomicInteger

class UserspaceWgEndpointTest {

    @Test
    fun `configure forwards to backend`() {
        val backend = FakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        endpoint.configure("private_key=00\nlisten_port=51820\n")
        assertEquals(listOf("private_key=00\nlisten_port=51820\n"), backend.uapiCalls)
    }

    @Test
    fun `setProtector forwards to backend`() {
        val backend = FakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        val protector = object : WgFdProtector { override fun protect(fd: Int) = true }
        endpoint.setProtector(protector)
        assertEquals(listOf<WgFdProtector?>(protector), backend.protectors)
    }

    @Test
    fun `setProtector accepts null to clear`() {
        val backend = FakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        endpoint.setProtector(null)
        assertEquals(listOf<WgFdProtector?>(null), backend.protectors)
    }

    @Test
    fun `close closes backend`() {
        val backend = FakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        endpoint.close()
        assertEquals(1, backend.closeCount.get())
        assertTrue(endpoint.isClosed)
    }

    @Test
    fun `close is idempotent`() {
        val backend = FakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        endpoint.close()
        endpoint.close()
        endpoint.close()
        assertEquals(1, backend.closeCount.get())
    }

    @Test
    fun `configure after close throws`() {
        val backend = FakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        endpoint.close()
        assertThrows(IllegalStateException::class.java) {
            endpoint.configure("private_key=00\n")
        }
    }

    @Test
    fun `setProtector after close is a silent no-op`() {
        val backend = FakeBackend()
        val endpoint = UserspaceWgEndpoint(backend)
        endpoint.close()
        endpoint.setProtector(object : WgFdProtector { override fun protect(fd: Int) = true })
        // Backend wasn't called post-close; only the close() event recorded.
        assertEquals(0, backend.protectors.size)
    }

    @Test
    fun `close swallows backend exceptions so it can't deadlock teardown`() {
        val backend = FakeBackend(throwOnClose = true)
        val endpoint = UserspaceWgEndpoint(backend)
        // Must not throw — close() is the last-ditch teardown path
        // and a service shutting down can't surface this any further.
        endpoint.close()
        assertTrue(endpoint.isClosed)
    }

    @Test
    fun `isClosed starts false`() {
        val endpoint = UserspaceWgEndpoint(FakeBackend())
        assertFalse(endpoint.isClosed)
    }

    @Test
    fun `configure propagates backend errors`() {
        val backend = FakeBackend(uapiError = IOException("bad config"))
        val endpoint = UserspaceWgEndpoint(backend)
        val ex = assertThrows(IOException::class.java) {
            endpoint.configure("garbage")
        }
        assertEquals("bad config", ex.message)
    }

    private class FakeBackend(
        private val uapiError: Exception? = null,
        private val throwOnClose: Boolean = false,
    ) : WgBridgeBackend {
        val uapiCalls = mutableListOf<String>()
        val protectors = mutableListOf<WgFdProtector?>()
        val closeCount = AtomicInteger(0)

        override fun configureUapi(uapi: String) {
            uapiError?.let { throw it }
            uapiCalls += uapi
        }
        override fun listenTcp(port: Int, acceptor: WgTcpAcceptor) {
            error("not exercised in lifecycle tests")
        }
        override fun listenUdp(port: Int, receiver: WgUdpReceiver): WgUdpSink =
            error("not exercised in lifecycle tests")
        override fun setFdProtector(protector: WgFdProtector?) { protectors += protector }
        override fun close() {
            closeCount.incrementAndGet()
            if (throwOnClose) throw IOException("close failed")
        }
    }
}
