package com.gutschke.wgrtc.signalling

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.concurrent.thread

/**
 * Unit + integration tests for [Stun].
 *
 * The unit tests verify wire-format encode/decode against vectors
 * crafted by hand (no I/O). The integration tests spin up a tiny
 * RFC 5389 STUN responder on the loopback and probe it through the
 * real [StunClient] — same approach the Python tests use, so we
 * inherit the daemon's confidence that the code matches over-the-
 * wire reality.
 */
class StunTest {

    // ─── Wire-format unit tests ──────────────────────────────────────────

    @Test fun `binding request has correct shape`() {
        val txid = ByteArray(12) { it.toByte() } // 0x00..0x0b
        val req = buildStunBindingRequest(txid)
        assertEquals(20, req.size)
        // Type = 0x0001 (binding request), Length = 0
        val bb = ByteBuffer.wrap(req).order(ByteOrder.BIG_ENDIAN)
        assertEquals(0x0001.toShort(), bb.getShort())
        assertEquals(0.toShort(), bb.getShort())
        // Magic cookie = 0x2112A442
        assertEquals(0x2112A442.toInt(), bb.getInt())
        // Transaction id matches what we passed.
        val gotTxid = ByteArray(12).also { bb.get(it) }
        assertArrayEquals(txid, gotTxid)
    }

    @Test fun `parses a hand-crafted XOR-MAPPED-ADDRESS response`() {
        val txid = ByteArray(12) { 0x42.toByte() }
        // Build a synthetic response containing XOR-MAPPED-ADDRESS for
        // 203.0.113.42:54321.
        val ext = pack(203, 0, 113, 42)
        val srcPort = 54321
        val xport = srcPort xor (0x2112A442.ushr(16))
        val xip = ByteBuffer.wrap(ext).order(ByteOrder.BIG_ENDIAN).getInt() xor 0x2112A442.toInt()
        val attrPayload = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN)
            .put(0) // reserved
            .put(0x01) // family = IPv4
            .putShort(xport.toShort())
            .putInt(xip)
            .array()
        val attr = ByteBuffer.allocate(4 + attrPayload.size).order(ByteOrder.BIG_ENDIAN)
            .putShort(0x0020) // XOR-MAPPED-ADDRESS
            .putShort(attrPayload.size.toShort())
            .put(attrPayload)
            .array()
        val response = ByteBuffer.allocate(20 + attr.size).order(ByteOrder.BIG_ENDIAN)
            .putShort(0x0101) // binding response
            .putShort(attr.size.toShort())
            .putInt(0x2112A442.toInt()) // magic cookie
            .put(txid)
            .put(attr)
            .array()

        val parsed = parseStunBindingResponse(response, txid)
        assertEquals(StunMapping("203.0.113.42", 54321), parsed)
    }

    @Test fun `mismatched txid returns null`() {
        val txid = ByteArray(12) { 0x42.toByte() }
        val wrongTxid = ByteArray(12) { 0x99.toByte() }
        val resp = ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN)
            .putShort(0x0101)
            .putShort(0)
            .putInt(0x2112A442.toInt())
            .put(wrongTxid)
            .array()
        assertNull(parseStunBindingResponse(resp, txid))
    }

    @Test fun `missing XOR-MAPPED-ADDRESS returns null`() {
        val txid = ByteArray(12) { 0x42.toByte() }
        val resp = ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN)
            .putShort(0x0101)
            .putShort(0)
            .putInt(0x2112A442.toInt())
            .put(txid)
            .array()
        assertNull(parseStunBindingResponse(resp, txid))
    }

    @Test fun `wrong message type returns null`() {
        val txid = ByteArray(12) { 0x42.toByte() }
        val resp = ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN)
            .putShort(0x0001) // BINDING REQUEST type, not response
            .putShort(0)
            .putInt(0x2112A442.toInt())
            .put(txid)
            .array()
        assertNull(parseStunBindingResponse(resp, txid))
    }

    @Test fun `ipv6 family is currently rejected (we ship v4 only)`() {
        val txid = ByteArray(12) { 0x42.toByte() }
        val attrPayload = ByteArray(20) // family=0x02 (IPv6) at byte 1, no rest matters
        attrPayload[1] = 0x02
        val attr = ByteBuffer.allocate(4 + attrPayload.size).order(ByteOrder.BIG_ENDIAN)
            .putShort(0x0020)
            .putShort(attrPayload.size.toShort())
            .put(attrPayload)
            .array()
        val resp = ByteBuffer.allocate(20 + attr.size).order(ByteOrder.BIG_ENDIAN)
            .putShort(0x0101)
            .putShort(attr.size.toShort())
            .putInt(0x2112A442.toInt())
            .put(txid)
            .put(attr)
            .array()
        assertNull(parseStunBindingResponse(resp, txid))
    }

    // ─── Integration — talk to a tiny in-process responder ───────────────

    @Test fun `probe gets correct mapping from stub server`() {
        StubStunServer().use { stub ->
            val client = StunClient(timeoutMs = 2000)
            val mapping = client.probe("127.0.0.1:${stub.port}")
            assertNotNull(mapping)
            // Loopback echoes back the source — external IP/port are
            // exactly the source the kernel chose for our socket.
            assertEquals("127.0.0.1", mapping!!.externalIp)
            assertTrue(mapping.externalPort in 1024..65535)
        }
    }

    @Test fun `probe times out cleanly when server is silent`() {
        // Bind a port with no responder so the probe times out.
        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { silent ->
            val client = StunClient(timeoutMs = 250)
            val mapping = client.probe("127.0.0.1:${silent.localPort}")
            assertNull(mapping)
        }
    }

    @Test fun `classify returns CONE_PRESERVING when same source port maps the same`() {
        StubStunServer().use { stub ->
            val client = StunClient(timeoutMs = 2000)
            val report = classifyNat(
                servers = listOf("127.0.0.1:${stub.port}", "127.0.0.1:${stub.port}"),
                client = client,
            )
            assertEquals(NatType.CONE_PRESERVING, report.natType)
            // External IP is consistent.
            assertEquals("127.0.0.1", report.externalIp)
        }
    }

    @Test fun `classify returns SYMMETRIC when external port differs per server`() {
        // Two stubs, but lie: one always reports a fixed (different) port.
        StubStunServer().use { honest ->
            FixedPortStubStunServer(advertisedPort = 19999).use { liar ->
                val client = StunClient(timeoutMs = 2000)
                val report = classifyNat(
                    servers = listOf(
                        "127.0.0.1:${honest.port}",
                        "127.0.0.1:${liar.port}",
                    ),
                    client = client,
                )
                assertEquals(NatType.SYMMETRIC, report.natType)
            }
        }
    }

    @Test fun `classify returns UNKNOWN when all servers fail`() {
        val client = StunClient(timeoutMs = 200)
        // Pick three ports very unlikely to be in use.
        val report = classifyNat(
            servers = listOf("127.0.0.1:9", "127.0.0.1:9", "127.0.0.1:9"),
            client = client,
        )
        assertEquals(NatType.UNKNOWN, report.natType)
        assertNull(report.externalIp)
    }

    // ─── Helpers ────────────────────────────────────────────────────────

    private fun pack(a: Int, b: Int, c: Int, d: Int): ByteArray =
        byteArrayOf(a.toByte(), b.toByte(), c.toByte(), d.toByte())

    /** Tiny in-process STUN responder — echoes (src_ip, src_port). */
    private class StubStunServer : AutoCloseable {
        val sock: DatagramSocket = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val port: Int get() = sock.localPort
        @Volatile private var stop = false
        private val t = thread(start = true, isDaemon = true) {
            val buf = ByteArray(2048)
            sock.soTimeout = 100
            while (!stop) {
                val pkt = DatagramPacket(buf, buf.size)
                try { sock.receive(pkt) } catch (_: Exception) { continue }
                val data = pkt.data.copyOfRange(0, pkt.length)
                if (data.size < 20) continue
                val bb = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
                val type = bb.getShort()
                bb.getShort() // length
                val cookie = bb.getInt()
                val txid = ByteArray(12).also { bb.get(it) }
                if (type != 0x0001.toShort() || cookie != 0x2112A442.toInt()) continue
                val resp = buildXorMappedResponse(
                    txid = txid,
                    srcIp = pkt.address.hostAddress!!,
                    srcPort = pkt.port,
                )
                sock.send(DatagramPacket(resp, resp.size, pkt.address, pkt.port))
            }
        }
        override fun close() {
            stop = true
            sock.close()
            t.join(500)
        }
    }

    /** Stub that always reports a fixed external port — used to fake a
     * symmetric-NAT outcome (different ports per server). */
    private class FixedPortStubStunServer(
        val advertisedPort: Int,
    ) : AutoCloseable {
        val sock: DatagramSocket = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val port: Int get() = sock.localPort
        @Volatile private var stop = false
        private val t = thread(start = true, isDaemon = true) {
            val buf = ByteArray(2048)
            sock.soTimeout = 100
            while (!stop) {
                val pkt = DatagramPacket(buf, buf.size)
                try { sock.receive(pkt) } catch (_: Exception) { continue }
                val data = pkt.data.copyOfRange(0, pkt.length)
                if (data.size < 20) continue
                val bb = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
                val type = bb.getShort()
                bb.getShort() // length
                val cookie = bb.getInt()
                val txid = ByteArray(12).also { bb.get(it) }
                if (type != 0x0001.toShort() || cookie != 0x2112A442.toInt()) continue
                val resp = buildXorMappedResponse(
                    txid = txid,
                    srcIp = pkt.address.hostAddress!!,
                    srcPort = advertisedPort,
                )
                sock.send(DatagramPacket(resp, resp.size, pkt.address, pkt.port))
            }
        }
        override fun close() {
            stop = true
            sock.close()
            t.join(500)
        }
    }

}

private fun buildXorMappedResponse(
    txid: ByteArray, srcIp: String, srcPort: Int,
): ByteArray {
    val ipBytes = InetAddress.getByName(srcIp).address
    val xport = srcPort xor (0x2112A442.ushr(16))
    val xip = ByteBuffer.wrap(ipBytes).order(ByteOrder.BIG_ENDIAN).getInt() xor 0x2112A442.toInt()
    val attrPayload = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN)
        .put(0).put(0x01).putShort(xport.toShort()).putInt(xip)
        .array()
    val attr = ByteBuffer.allocate(4 + attrPayload.size).order(ByteOrder.BIG_ENDIAN)
        .putShort(0x0020).putShort(attrPayload.size.toShort()).put(attrPayload)
        .array()
    return ByteBuffer.allocate(20 + attr.size).order(ByteOrder.BIG_ENDIAN)
        .putShort(0x0101)
        .putShort(attr.size.toShort())
        .putInt(0x2112A442.toInt())
        .put(txid)
        .put(attr)
        .array()
}
