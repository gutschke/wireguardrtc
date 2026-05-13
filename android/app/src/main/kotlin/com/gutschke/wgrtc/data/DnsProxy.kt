package com.gutschke.wgrtc.data

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.UnknownHostException

/**
 * Thin DNS resolver abstraction so [DnsProxy] is testable
 * without touching the OS resolver. Production wires this to
 * `InetAddress.getAllByName(name)` (optionally bound to an
 * Android [android.net.Network] handle when 's
 * `EgressSelector` is in scope).
 */
interface DnsResolver {
    /** Resolve [name] to one or more addresses. May return both
     * IPv4 and IPv6. Throws [UnknownHostException] on NXDOMAIN
     * / SERVFAIL. Implementations may block. */
    @Throws(UnknownHostException::class)
    fun resolve(name: String): List<InetAddress>
}

/**
 * **userspace DNS proxy.**
 *
 * Accepts a DNS query as a UDP datagram payload, resolves the
 * QNAME via [resolver], and synthesizes a syntactically-valid
 * response in RFC 1035 wire format. The response carries the
 * same TXID and question section the client sent (RFC 1035
 * §6.1: "the response message must contain the same Question
 * section as the corresponding query").
 *
 * **Scope.** This implementation handles the queries clients
 * actually send through a tunnel:
 *
 * - A (type 1) and AAAA (type 28) lookups, IN class.
 * - One question per query (§4.1.2 says technically multiple
 * are allowed but every modern resolver sends exactly one).
 * - UDP transport with a 512-byte response cap; sets the TC
 * flag when truncating, signaling the client to retry over
 * TCP. TCP fallback is plumbed by [DnsTcpHandler] (see
 * same file).
 *
 * **NOT supported (returns NOTIMP):** SRV, MX, TXT, ANY, AXFR,
 * EDNS0 OPT. These rarely appear in tunnelled traffic; a
 * future iteration can extend this if a real client needs them.
 *
 * **Why we synthesize responses ourselves rather than blob-
 * forwarding to an upstream resolver.** The forwarder model
 * (read query, forward verbatim to 8.8.8.8, blob the response
 * back) is conceptually simpler but has a privacy + integrity
 * downside: it routes every joiner DNS query through whichever
 * upstream we picked, exposing the joiner's name lookups to
 * that operator. Going through `InetAddress.getAllByName()`
 * lets the resolution use the phone's normal resolver chain
 * (system DNS, possibly upgraded to DoH), which the user has
 * already evaluated as part of trusting the phone's network
 * configuration. The phone's choice of resolver becomes the
 * tunnel's choice of resolver; one privacy boundary, not two.
 *
 * **Thread safety.** [handle] is stateless beyond the resolver
 * lookup, so concurrent calls are safe. [resolver] must be
 * concurrent-safe (the production wiring uses
 * `InetAddress.getAllByName` which is thread-safe via the
 * JVM resolver cache).
 */
class DnsProxy(private val resolver: DnsResolver) {

    /**
     * Process one inbound query datagram and return the response
     * bytes, or null if the query was malformed (in which case
     * we drop silently — RFC 1035 §6.1.1 doesn't require us to
     * answer garbage, and answering with FORMERR opens a small
     * amplification surface).
     */
    fun handle(queryBuf: ByteArray): ByteArray? {
        if (queryBuf.size < HEADER_LEN) return null
        val txid = ((queryBuf[0].toInt() and 0xff) shl 8) or (queryBuf[1].toInt() and 0xff)
        val qdCount = ((queryBuf[4].toInt() and 0xff) shl 8) or (queryBuf[5].toInt() and 0xff)
        if (qdCount != 1) return null // see "scope" — one question only

        // Parse the question's QNAME.
        val q = parseQuestion(queryBuf, HEADER_LEN) ?: return null
        val qname = q.name
        val qtype = q.qtype
        val qclass = q.qclass

        // RFC says class 1 = IN; we don't bother answering CHAOS
        // / HS queries.
        if (qclass != CLASS_IN) {
            return buildResponse(txid, queryBuf, q, RCODE_NOTIMP, emptyList())
        }
        // Only A + AAAA are handled.
        if (qtype != TYPE_A && qtype != TYPE_AAAA) {
            return buildResponse(txid, queryBuf, q, RCODE_NOTIMP, emptyList())
        }

        val addrs = try {
            resolver.resolve(qname)
        } catch (_: UnknownHostException) {
            return buildResponse(txid, queryBuf, q, RCODE_NXDOMAIN, emptyList())
        } catch (_: Throwable) {
            return buildResponse(txid, queryBuf, q, RCODE_SERVFAIL, emptyList())
        }

        // Filter to the requested family.
        val filtered = addrs.filter { addr ->
            when (qtype) {
                TYPE_A -> addr is Inet4Address
                TYPE_AAAA -> addr is Inet6Address
                else -> false
            }
        }
        if (filtered.isEmpty()) {
            // Resolver knew the name but had no matching family
            // (e.g., AAAA query against an A-only host). RFC
            // 6147 §5.1.6 — return NOERROR + empty answer (NODATA).
            return buildResponse(txid, queryBuf, q, RCODE_NOERROR, emptyList())
        }
        return buildResponse(txid, queryBuf, q, RCODE_NOERROR, filtered.map { it.address })
    }

    // ── RFC 1035 wire-format encode/decode ───────────────────

    private data class Question(
        val name: String,
        val qtype: Int,
        val qclass: Int,
        /** Byte offset just past the encoded qname + qtype + qclass. */
        val endOffset: Int,
        /** Byte offset where the qname starts (= startOffset). */
        val nameStart: Int,
    )

    /** Decode the question at [offset]. Returns null on
     * malformed input (label-length overrun, missing root
     * null, etc.). Does NOT support compression pointers in
     * the question section — clients never use them in the
     * question. */
    private fun parseQuestion(buf: ByteArray, offset: Int): Question? {
        val sb = StringBuilder()
        var p = offset
        var first = true
        while (p < buf.size) {
            val len = buf[p].toInt() and 0xff
            if (len == 0) { p++; break }
            if (len and 0xc0 != 0) return null // pointer in question — refuse
            if (p + 1 + len > buf.size) return null
            if (!first) sb.append('.')
            for (i in 0 until len) sb.append((buf[p + 1 + i].toInt() and 0xff).toChar())
            p += 1 + len
            first = false
        }
        if (p + 4 > buf.size) return null
        val qtype = ((buf[p].toInt() and 0xff) shl 8) or (buf[p + 1].toInt() and 0xff)
        val qclass = ((buf[p + 2].toInt() and 0xff) shl 8) or (buf[p + 3].toInt() and 0xff)
        return Question(
            name = sb.toString(),
            qtype = qtype,
            qclass = qclass,
            endOffset = p + 4,
            nameStart = offset,
        )
    }

    /** Build a response with [rcode] and zero-or-more answer
     * records. Truncates + sets TC if the result would exceed
     * [UDP_MAX_RESPONSE_BYTES]; the question section + at
     * least the header are always kept intact. */
    private fun buildResponse(
        txid: Int,
        queryBuf: ByteArray,
        q: Question,
        rcode: Int,
        rdataList: List<ByteArray>,
    ): ByteArray {
        // Compute response size up front so we know whether we
        // need to truncate. Each A answer = qname (using
        // compression pointer to the question, 2 B) + type 2 B
        // + class 2 B + ttl 4 B + rdlen 2 B + rdata 4/16 B.
        val ansBaseSize = 12 // type + class + ttl + rdlen
        val ansRecordSizes = rdataList.map { 2 /* compression ptr */ + ansBaseSize + it.size }
        val questionSize = q.endOffset - q.nameStart
        val baseSize = HEADER_LEN + questionSize

        // How many answers fit in [UDP_MAX_RESPONSE_BYTES]?
        var fits = 0
        var size = baseSize
        for (s in ansRecordSizes) {
            if (size + s > UDP_MAX_RESPONSE_BYTES) break
            size += s; fits++
        }
        val truncated = fits < rdataList.size
        val included = rdataList.take(fits)
        val out = ByteArray(size)

        // ── Header ─────────────────────────────────────
        out[0] = (txid ushr 8 and 0xff).toByte()
        out[1] = (txid and 0xff).toByte()
        // Flags (RFC 1035 §4.1.1): QR=1, Opcode=0, AA=0, TC?,
        // RD=mirrored, RA=1, Z=0, RCODE. RD lives in byte 2
        // bit 0 of the query (high byte of flags); we mirror it
        // so the client sees "RD got honored." TC is bit 1 of
        // byte 2; RA is the high bit of byte 3.
        var flags = 0x8000 // QR=1
        if (queryBuf[2].toInt() and 0x01 != 0) flags = flags or 0x0100 // mirror RD
        if (truncated) flags = flags or 0x0200 // TC=1
        flags = flags or 0x0080 // RA=1 (we recurse via the OS resolver)
        flags = flags or (rcode and 0x0f)
        out[2] = (flags ushr 8 and 0xff).toByte()
        out[3] = (flags and 0xff).toByte()
        // QDCOUNT=1, ANCOUNT=fits, NSCOUNT=0, ARCOUNT=0
        out[4] = 0; out[5] = 1
        out[6] = (fits ushr 8 and 0xff).toByte(); out[7] = (fits and 0xff).toByte()
        out[8] = 0; out[9] = 0
        out[10] = 0; out[11] = 0

        // ── Question (copied byte-for-byte from query) ─
        System.arraycopy(queryBuf, q.nameStart, out, HEADER_LEN, questionSize)

        // ── Answers ───────────────────────────────────
        var p = HEADER_LEN + questionSize
        for (rdata in included) {
            // Compression pointer to the question's qname. In
            // our fixed layout the qname starts at offset 12
            // (= HEADER_LEN), so the low octet of the pointer
            // is always 12 and the high two bits are the 0xc0
            // marker.
            out[p++] = 0xc0.toByte()
            out[p++] = q.nameStart.toByte()
            // TYPE
            out[p++] = (q.qtype ushr 8 and 0xff).toByte()
            out[p++] = (q.qtype and 0xff).toByte()
            // CLASS = IN
            out[p++] = 0; out[p++] = 1
            // TTL — short, deliberately. 60 s gives clients a
            // chance to refresh after a network change without
            // hammering us.
            out[p++] = 0; out[p++] = 0; out[p++] = 0; out[p++] = 60
            // RDLENGTH
            out[p++] = (rdata.size ushr 8 and 0xff).toByte()
            out[p++] = (rdata.size and 0xff).toByte()
            // RDATA
            System.arraycopy(rdata, 0, out, p, rdata.size)
            p += rdata.size
        }
        return out
    }

    companion object {
        private const val HEADER_LEN = 12

        /** UDP transport's response cap. Above this we set TC
         * and the client retries over TCP per RFC 5966. */
        const val UDP_MAX_RESPONSE_BYTES = 512

        // Wire-format constants we care about (RFC 1035 §3.2.2 + §3.2.4).
        private const val TYPE_A = 1
        private const val TYPE_AAAA = 28
        private const val CLASS_IN = 1
        private const val RCODE_NOERROR = 0
        private const val RCODE_NXDOMAIN = 3
        private const val RCODE_NOTIMP = 4
        private const val RCODE_SERVFAIL = 2
    }
}
