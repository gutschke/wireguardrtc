package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/**
 * **DNS proxy unit tests.**
 *
 * Pins the wire-format details that determine whether the
 * proxy is interoperable with real-world resolvers:
 *
 * - The TXID must round-trip exactly so the requesting client
 * can correlate response → query.
 * - Every well-formed query must produce a syntactically
 * valid response (header + question + answers).
 * - Truncated responses (UDP > 512 bytes) must set the TC flag
 * so the client knows to retry over TCP.
 * - Malformed input must NOT crash the proxy; either drop
 * silently or return FORMERR.
 * - Concurrent queries must not cross-contaminate.
 *
 * The resolver is mocked here — production wires it to
 * `InetAddress.getAllByName()` via the [EgressSelector] plumbing
 * in , which is also where Network-handle-bound resolution
 * lives. Unit tests stay fast + deterministic by injecting a
 * fake.
 */
class DnsProxyTest {

    // ── Helpers ──────────────────────────────────────────────

    /** Build a minimal DNS query for `name` of type [qtype].
     * RFC 1035 §4.1.1 header + §4.1.2 question. */
    private fun buildQuery(txid: Int, name: String, qtype: Int = 1 /* A */): ByteArray {
        val labels = name.trim('.').split('.').filter { it.isNotEmpty() }
        val qnameSize = labels.sumOf { 1 + it.length } + 1 // +1 root null
        val buf = ByteArray(12 + qnameSize + 4)
        // Header
        buf[0] = (txid ushr 8 and 0xff).toByte()
        buf[1] = (txid and 0xff).toByte()
        buf[2] = 0x01 // RD=1, QR=0, opcode=0
        buf[3] = 0x00
        buf[4] = 0; buf[5] = 1 // qdcount=1
        buf[6] = 0; buf[7] = 0
        buf[8] = 0; buf[9] = 0
        buf[10] = 0; buf[11] = 0
        // Question — qname
        var p = 12
        for (lbl in labels) {
            buf[p++] = lbl.length.toByte()
            for (ch in lbl) buf[p++] = ch.code.toByte()
        }
        buf[p++] = 0
        // qtype + qclass
        buf[p++] = (qtype ushr 8 and 0xff).toByte()
        buf[p++] = (qtype and 0xff).toByte()
        buf[p++] = 0; buf[p] = 1 // qclass = IN
        return buf
    }

    private fun txid(buf: ByteArray): Int =
        ((buf[0].toInt() and 0xff) shl 8) or (buf[1].toInt() and 0xff)

    private fun flags(buf: ByteArray): Int =
        ((buf[2].toInt() and 0xff) shl 8) or (buf[3].toInt() and 0xff)

    private fun rcode(buf: ByteArray): Int = buf[3].toInt() and 0x0f
    private fun qr(buf: ByteArray): Int = (buf[2].toInt() ushr 7) and 0x01
    private fun tc(buf: ByteArray): Int = (buf[2].toInt() ushr 1) and 0x01
    private fun answerCount(buf: ByteArray): Int =
        ((buf[6].toInt() and 0xff) shl 8) or (buf[7].toInt() and 0xff)

    /** A fake [DnsResolver] returning a fixed list of addresses
     * for any query. Throws on a nominated failure name. */
    private class FakeResolver(
        private val responses: Map<String, List<InetAddress>> = emptyMap(),
        private val failOn: Set<String> = emptySet(),
    ) : DnsResolver {
        override fun resolve(name: String): List<InetAddress> {
            if (name.lowercase().trim('.') in failOn) {
                throw java.net.UnknownHostException(name)
            }
            return responses[name.lowercase().trim('.')] ?: emptyList()
        }
    }

    // ── Tests ────────────────────────────────────────────────

    @Test fun `A query for a known name returns one A record with same TXID`() {
        val proxy = DnsProxy(resolver = FakeResolver(responses = mapOf(
            "example.com" to listOf(Inet4Address.getByAddress(byteArrayOf(1, 2, 3, 4)))
        )))
        val q = buildQuery(txid = 0xABCD, name = "example.com")
        val r = proxy.handle(q)
        assertNotNull(r, "proxy must answer")
        r!!
        assertEquals(0xABCD, txid(r), "TXID round-trip")
        assertEquals(1, qr(r), "QR bit set on response")
        assertEquals(0, rcode(r), "RCODE 0 = NOERROR")
        assertEquals(1, answerCount(r), "exactly one A record")
        // The answer's RDATA is at offset = 12 (header) + qname-size
        // + 4 (qtype + qclass) + 12 (RR header up to RDATA).
        // Given qname "example.com" (1 + 7 + 1 + 3 + 1 = 13 bytes),
        // the response layout is fully determined; verify by
        // searching for the bytes 1.2.3.4.
        val ip = byteArrayOf(1, 2, 3, 4)
        var found = false
        for (i in 0..(r.size - 4)) {
            if (r[i] == ip[0] && r[i + 1] == ip[1] &&
                r[i + 2] == ip[2] && r[i + 3] == ip[3]) {
                found = true; break
            }
        }
        assertTrue(found, "1.2.3.4 not present in response RDATA")
    }

    @Test fun `unknown name returns NXDOMAIN`() {
        val proxy = DnsProxy(resolver = FakeResolver(failOn = setOf("nope.example")))
        val q = buildQuery(txid = 1, name = "nope.example")
        val r = proxy.handle(q)
        assertNotNull(r)
        assertEquals(3, rcode(r!!), "RCODE 3 = NXDOMAIN")
        assertEquals(0, answerCount(r), "no answers")
    }

    @Test fun `unsupported qtype returns NOTIMP, not crash`() {
        val proxy = DnsProxy(resolver = FakeResolver())
        // Type 99 — not anything we handle.
        val q = buildQuery(txid = 1, name = "any.com", qtype = 99)
        val r = proxy.handle(q)
        assertNotNull(r)
        // RCODE 4 = NOTIMP per RFC 1035 §4.1.1.
        assertEquals(4, rcode(r!!))
    }

    @Test fun `AAAA query is supported and returns IPv6 records`() {
        val ip6 = byteArrayOf(
            0x20.toByte(), 0x01.toByte(), 0x0d.toByte(), 0xb8.toByte(),
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        )
        val proxy = DnsProxy(resolver = FakeResolver(responses = mapOf(
            "v6.example" to listOf(Inet6Address.getByAddress(ip6))
        )))
        val q = buildQuery(txid = 2, name = "v6.example", qtype = 28 /* AAAA */)
        val r = proxy.handle(q)
        assertNotNull(r)
        assertEquals(0, rcode(r!!), "NOERROR for known AAAA")
        assertEquals(1, answerCount(r))
    }

    @Test fun `truncated response sets TC flag when above 512 byte UDP cap`() {
        // Construct a query whose response would exceed 512 B.
        // 60 IPv4 addrs × ~16 B per A RR = ~960 B body;
        // total > 512. The proxy should truncate and set TC.
        val many = (1..60).map {
            Inet4Address.getByAddress(byteArrayOf(10, 0, 0, it.toByte()))
        }
        val proxy = DnsProxy(resolver = FakeResolver(responses = mapOf(
            "big.example" to many
        )))
        val q = buildQuery(txid = 3, name = "big.example")
        val r = proxy.handle(q)
        assertNotNull(r)
        assertTrue(r!!.size <= 512, "must respect 512-byte UDP cap")
        assertEquals(1, tc(r), "TC flag should be set on truncated reply")
    }

    @Test fun `malformed query returns null - no crash`() {
        val proxy = DnsProxy(resolver = FakeResolver())
        // Too short for a header.
        assertNull(proxy.handle(byteArrayOf(0, 1, 2)))
        // Header says 1 question but body is empty.
        val truncated = ByteArray(12).apply {
            this[5] = 1 // qdcount=1
        }
        assertNull(proxy.handle(truncated))
    }

    @Test fun `parallel queries with distinct TXIDs do not cross-contaminate`() {
        val proxy = DnsProxy(resolver = FakeResolver(responses = mapOf(
            "a.example" to listOf(Inet4Address.getByAddress(byteArrayOf(10, 0, 0, 1))),
            "b.example" to listOf(Inet4Address.getByAddress(byteArrayOf(10, 0, 0, 2))),
        )))
        val r1 = proxy.handle(buildQuery(txid = 0x1111, name = "a.example"))
        val r2 = proxy.handle(buildQuery(txid = 0x2222, name = "b.example"))
        assertNotNull(r1); assertNotNull(r2)
        assertEquals(0x1111, txid(r1!!))
        assertEquals(0x2222, txid(r2!!))
        assertNotEquals(txid(r1), txid(r2), "TXIDs must be preserved per query")
    }

    @Test fun `qname is preserved exactly in the response question section`() {
        val proxy = DnsProxy(resolver = FakeResolver(responses = mapOf(
            "example.com" to listOf(Inet4Address.getByAddress(byteArrayOf(1, 2, 3, 4)))
        )))
        val q = buildQuery(txid = 0xBEEF, name = "example.com")
        val r = proxy.handle(q)!!
        // The response's question section is bytes 12 onward;
        // it must mirror the query's bytes 12..end-of-question.
        val qnameEnd = run {
            var p = 12
            while (p < q.size && q[p].toInt() != 0) p += (q[p].toInt() and 0xff) + 1
            p + 1 + 4 // root null + qtype + qclass
        }
        assertArrayEquals(
            q.copyOfRange(12, qnameEnd),
            r.copyOfRange(12, qnameEnd),
            "question section must be byte-identical between query and response"
        )
    }
}
