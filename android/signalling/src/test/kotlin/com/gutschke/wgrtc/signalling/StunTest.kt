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

    @Test fun `parses XOR-MAPPED-ADDRESS after a padded unknown attribute`() {
        // Regression: real STUN servers (Google's stun.l.google.com,
        // for one) emit a SOFTWARE attribute before XOR-MAPPED-ADDRESS.
        // SOFTWARE is a UTF-8 string and its length rarely lands on
        // a 4-byte boundary, so STUN's per-attribute padding kicks in.
        // The parser's skip-unknown-attribute path used to advance
        // ByteBuffer.position by raw attrLen (not alignTo4(attrLen)),
        // so the next attribute's header was read from the padding
        // bytes — XOR-MAPPED-ADDRESS got missed and probe() returned
        // null. Symptom: STUN classification falsely flagged as
        // UNKNOWN on stacks that hit a server with this layout.
        val txid = ByteArray(12) { 0x42.toByte() }
        // Unknown attribute: type=0x8022 (SOFTWARE), payload="hello"
        // (5 bytes — needs 3 bytes of zero padding).
        val swPayload = "hello".toByteArray(Charsets.UTF_8)
        assertEquals(5, swPayload.size)
        val swAttr = ByteBuffer.allocate(4 + 5 + 3) // header + payload + pad
            .order(ByteOrder.BIG_ENDIAN)
            .putShort(0x8022.toShort())
            .putShort(5.toShort())
            .put(swPayload)
            .put(byteArrayOf(0, 0, 0)) // padding to next 4-byte boundary
            .array()
        // Then XOR-MAPPED-ADDRESS for 203.0.113.42:54321.
        val srcPort = 54321
        val xport = srcPort xor (0x2112A442.ushr(16))
        val xip = ByteBuffer.wrap(pack(203, 0, 113, 42))
            .order(ByteOrder.BIG_ENDIAN).getInt() xor 0x2112A442.toInt()
        val xmAttrPayload = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN)
            .put(0).put(0x01).putShort(xport.toShort()).putInt(xip)
            .array()
        val xmAttr = ByteBuffer.allocate(4 + xmAttrPayload.size)
            .order(ByteOrder.BIG_ENDIAN)
            .putShort(0x0020).putShort(xmAttrPayload.size.toShort())
            .put(xmAttrPayload).array()
        val body = swAttr + xmAttr
        val response = ByteBuffer.allocate(20 + body.size)
            .order(ByteOrder.BIG_ENDIAN)
            .putShort(0x0101) // binding response
            .putShort(body.size.toShort())
            .putInt(0x2112A442.toInt())
            .put(txid)
            .put(body)
            .array()
        assertEquals(
            StunMapping("203.0.113.42", 54321),
            parseStunBindingResponse(response, txid),
        )
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

    @Test fun `parses a hand-crafted ipv6 XOR-MAPPED-ADDRESS response`() {
        // The case wgrtc was failing on: ChromeOS ARC resolves
        // stun.l.google.com's AAAA first, so the response carries
        // family=0x02 with a 16-byte XOR'd v6 mapped-address.
        // RFC 5389 §15.2: bytes 0..3 XOR magic cookie; bytes 4..15
        // XOR the 12-byte transaction id.
        val txid = ByteArray(12) { 0x42.toByte() }
        val srcPort = 51820
        val xport = srcPort xor (0x2112A442.ushr(16))
        // The address we want the parser to recover: 2001:db8::1
        val plainAddr = byteArrayOf(
            0x20, 0x01, 0x0d.toByte(), 0xb8.toByte(),
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 0x01,
        )
        val mask = ByteArray(16).also {
            // magic cookie BE
            it[0] = 0x21; it[1] = 0x12; it[2] = 0xa4.toByte(); it[3] = 0x42
            // txid (all 0x42 by construction)
            for (i in 4 until 16) it[i] = 0x42
        }
        val xoredAddr = ByteArray(16) { i -> (plainAddr[i].toInt() xor mask[i].toInt()).toByte() }

        val attrPayload = ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN)
            .put(0)            // reserved
            .put(0x02)         // family = IPv6
            .putShort(xport.toShort())
            .put(xoredAddr)
            .array()
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
        val parsed = parseStunBindingResponse(resp, txid)
        assertNotNull(parsed)
        assertEquals(51820, parsed!!.externalPort)
        // Compare via InetAddress so we don't have to commit to a
        // specific textual form (Java's compression has varied
        // between JDK versions).
        assertEquals(
            InetAddress.getByName("2001:db8::1"),
            InetAddress.getByName(parsed.externalIp),
        )
    }

    @Test fun `parses ipv6 ULA XOR-MAPPED-ADDRESS`() {
        // Same test shape as above but for ULA (fd00::/8) — the
        // Chromebook's eth5 carries an fd-prefixed ULA alongside the
        // global v6, and we want STUN to return either if that's
        // what the server sees.
        val txid = ByteArray(12) { (it + 1).toByte() }
        val plain = InetAddress.getByName(
            "fd00:a771:c05:0:9854:9eff:fe81:b49b").address
        val mask = ByteArray(16).also {
            it[0] = 0x21; it[1] = 0x12; it[2] = 0xa4.toByte(); it[3] = 0x42
            System.arraycopy(txid, 0, it, 4, 12)
        }
        val xored = ByteArray(16) { i -> (plain[i].toInt() xor mask[i].toInt()).toByte() }
        val srcPort = 22111
        val xport = srcPort xor (0x2112A442.ushr(16))

        val attrPayload = ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN)
            .put(0).put(0x02).putShort(xport.toShort()).put(xored).array()
        val attr = ByteBuffer.allocate(4 + 20).order(ByteOrder.BIG_ENDIAN)
            .putShort(0x0020).putShort(20.toShort()).put(attrPayload).array()
        val resp = ByteBuffer.allocate(20 + attr.size).order(ByteOrder.BIG_ENDIAN)
            .putShort(0x0101).putShort(attr.size.toShort())
            .putInt(0x2112A442.toInt()).put(txid).put(attr).array()
        val parsed = parseStunBindingResponse(resp, txid)
        assertNotNull(parsed)
        assertEquals(srcPort, parsed!!.externalPort)
        assertEquals(
            InetAddress.getByName("fd00:a771:c05:0:9854:9eff:fe81:b49b"),
            InetAddress.getByName(parsed.externalIp),
        )
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

    @Test fun `classify returns UNKNOWN for an empty server list`() {
        val report = classifyNat(servers = emptyList())
        assertEquals(NatType.UNKNOWN, report.natType)
        assertNull(report.externalIp)
        assertTrue(report.observations.isEmpty())
    }

    @Test fun `classify returns CONE_REMAPPED when port is consistent but != source`() {
        // Two stubs that both lie with the SAME fixed port — a single
        // external port observed across servers, but not equal to the
        // local source port we allocated.  This is what an upstream
        // cone NAT that remaps ports looks like.
        FixedPortStubStunServer(advertisedPort = 17171).use { a ->
            FixedPortStubStunServer(advertisedPort = 17171).use { b ->
                val client = StunClient(timeoutMs = 2000)
                val report = classifyNat(
                    servers = listOf(
                        "127.0.0.1:${a.port}",
                        "127.0.0.1:${b.port}",
                    ),
                    client = client,
                )
                assertEquals(NatType.CONE_REMAPPED, report.natType)
                assertEquals("127.0.0.1", report.externalIp)
                // Both observations should reflect the lied-about port.
                assertEquals(setOf(17171),
                    report.observations.map { it.externalPort }.toSet())
            }
        }
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
