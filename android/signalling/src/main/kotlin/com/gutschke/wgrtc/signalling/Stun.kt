package com.gutschke.wgrtc.signalling

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom

/**
 * RFC 5389 STUN binding-request client + a coarse NAT-type
 * classifier. Direct port of the daemon's `tests/01_stun_nat.py`.
 *
 * What this is for: host-mode (Android-as-WG-server) needs
 * to know whether the phone is behind a NAT type that allows
 * inbound hole-punching. If the phone is behind a SYMMETRIC NAT,
 * advertising its STUN-discovered public IP is meaningless — the
 * external port for traffic to a third party will differ from what
 * the STUN server saw. The phone refuses to claim inbound
 * reachability over PeerJS in that case.
 *
 * Pure JVM — no Android dependencies. Wire-format functions are
 * pure (testable with hand-crafted vectors); the I/O happens in
 * [StunClient] which can be replaced in tests by a stub server.
 *
 * Handles both XOR-MAPPED-ADDRESS families: IPv4 (family=0x01) and
 * IPv6 (family=0x02). The v6 path is critical on Android-on-ChromeOS
 * (ARC), where Java's [java.net.InetAddress.getByName] resolves a
 * dual-stack STUN server's AAAA before its A record; a v4-only parser
 * silently drops every reply and the host appears to have no NAT
 * classification at all. See PS19. Daemon-side STUN is still v4-only
 * (raw-inject hole-punching is v4-only); the v6 path here exists
 * because v6 doesn't need raw injection — it's end-to-end with no
 * NAT.
 */

private const val STUN_MAGIC_COOKIE: Int = 0x2112A442.toInt()
private const val STUN_MAGIC_COOKIE_HIGH16: Int = 0x2112 // upper 16 bits
private const val BINDING_REQUEST: Short = 0x0001
private const val BINDING_RESPONSE: Short = 0x0101
private const val XOR_MAPPED_ADDRESS: Short = 0x0020

/** Result of a single STUN probe — how this peer was seen externally. */
data class StunMapping(val externalIp: String, val externalPort: Int)

/** Coarse NAT classification used to gate inbound-reachability claims. */
enum class NatType {
    /** STUN external port equals the source port we used.
     * Hole-punch + advertise-port works as designed. */
    CONE_PRESERVING,

    /** External port is consistent across STUN servers but != source.
     * Daemon would publish the wrong port; needs a NAT-PMP/PCP probe
     * or bidirectional confirmation. Treat this as borderline. */
    CONE_REMAPPED,

    /** External port differs per destination. Hole-punch is
     * mathematically infeasible against a non-cone peer; the host
     * must NOT claim inbound reachability. */
    SYMMETRIC,

    /** Couldn't get any successful responses. No claim either way. */
    UNKNOWN,
}

/** Combined classification report. */
data class NatClassification(
    val natType: NatType,
    val externalIp: String?,
    /** All distinct (externalIp, externalPort) we observed; useful for
     * diagnostics when multiple STUN servers disagree. */
    val observations: List<StunMapping>,
    /** A short human-readable note suitable for log lines. */
    val note: String,
)

// ─── Wire format (pure functions; testable without I/O) ─────────────────

/** Build a 20-byte BINDING REQUEST with the given transaction id. */
fun buildStunBindingRequest(txid: ByteArray): ByteArray {
    require(txid.size == 12) { "txid must be exactly 12 bytes" }
    return ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN)
        .putShort(BINDING_REQUEST)
        .putShort(0) // length = 0
        .putInt(STUN_MAGIC_COOKIE)
        .put(txid)
        .array()
}

/** Generate a fresh 12-byte random transaction id. */
fun randomTxid(rng: SecureRandom = SecureRandom()): ByteArray =
    ByteArray(12).also { rng.nextBytes(it) }

/**
 * Parse a STUN BINDING RESPONSE and extract the XOR-MAPPED-ADDRESS.
 * Handles family=0x01 (IPv4, 8-byte attribute) and family=0x02 (IPv6,
 * 20-byte attribute). Returns null if the message isn't a successful
 * response, the transaction id doesn't match, the magic cookie is
 * wrong, or no XOR-MAPPED-ADDRESS attribute is present in a known
 * family.
 *
 * Per RFC 5389 §15.2 the address is XORed with the 4-byte magic
 * cookie (v4) or the cookie concatenated with the 12-byte transaction
 * id (v6). The port is XORed with the high 16 bits of the cookie in
 * both families.
 *
 * Returned [StunMapping.externalIp] is a bare textual literal — IPv4
 * dotted-quad or canonical IPv6 (compressed form via
 * [java.net.InetAddress]). Callers that need wire-form `host:port`
 * (with brackets around v6) should pass it through [formatEndpoint].
 */
fun parseStunBindingResponse(data: ByteArray, expectedTxid: ByteArray): StunMapping? {
    if (data.size < 20) return null
    val bb = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
    val type = bb.getShort()
    val msgLen = bb.getShort().toInt() and 0xFFFF
    val cookie = bb.getInt()
    val txid = ByteArray(12).also { bb.get(it) }
    if (type != BINDING_RESPONSE) return null
    if (cookie != STUN_MAGIC_COOKIE) return null
    if (!txid.contentEquals(expectedTxid)) return null
    if (data.size < 20 + msgLen) return null

    var offset = 20
    val end = 20 + msgLen
    while (offset + 4 <= end) {
        val attrType = bb.getShort()
        val attrLen = bb.getShort().toInt() and 0xFFFF
        if (offset + 4 + attrLen > end) return null
        if (attrType == XOR_MAPPED_ADDRESS && attrLen >= 8) {
            // attribute payload starts at current bb position.
            bb.get() // reserved, ignored
            val family = bb.get().toInt() and 0xFF
            val xport = bb.getShort().toInt() and 0xFFFF
            val extPort = xport xor STUN_MAGIC_COOKIE_HIGH16
            when (family) {
                0x01 -> {
                    // 4-byte IPv4 address XORed with the cookie.
                    val xip = bb.getInt()
                    val extIpInt = xip xor STUN_MAGIC_COOKIE
                    val ipBytes = ByteBuffer.allocate(4)
                        .order(ByteOrder.BIG_ENDIAN)
                        .putInt(extIpInt)
                        .array()
                    val extIp = "${ipBytes[0].toInt() and 0xFF}." +
                                "${ipBytes[1].toInt() and 0xFF}." +
                                "${ipBytes[2].toInt() and 0xFF}." +
                                "${ipBytes[3].toInt() and 0xFF}"
                    return StunMapping(extIp, extPort)
                }
                0x02 -> {
                    // 16-byte IPv6 address XORed with cookie ‖ txid.
                    if (attrLen < 20) {
                        // Malformed v6 attr; skip it.
                        bb.position(bb.position() + (attrLen - 4))
                        offset += 4 + alignTo4(attrLen)
                        continue
                    }
                    val raw = ByteArray(16).also { bb.get(it) }
                    val mask = ByteArray(16)
                    // First 4 bytes XOR with the magic cookie (big-endian).
                    mask[0] = ((STUN_MAGIC_COOKIE ushr 24) and 0xFF).toByte()
                    mask[1] = ((STUN_MAGIC_COOKIE ushr 16) and 0xFF).toByte()
                    mask[2] = ((STUN_MAGIC_COOKIE ushr 8) and 0xFF).toByte()
                    mask[3] = (STUN_MAGIC_COOKIE and 0xFF).toByte()
                    // Next 12 bytes XOR with the transaction id.
                    System.arraycopy(txid, 0, mask, 4, 12)
                    val ipBytes = ByteArray(16) { i -> (raw[i].toInt() xor mask[i].toInt()).toByte() }
                    val extIp = try {
                        java.net.InetAddress.getByAddress(ipBytes).hostAddress
                            ?: return null
                    } catch (_: Exception) { return null }
                    // Strip the Java %scopeId suffix if any — STUN never
                    // returns a scoped address, but defensive.
                    val cleanIp = extIp.substringBefore('%')
                    return StunMapping(cleanIp, extPort)
                }
                else -> {
                    // Unknown family; skip this attribute.
                    bb.position(bb.position() + (attrLen - 4))
                    offset += 4 + alignTo4(attrLen)
                    continue
                }
            }
        } else {
            // Skip this attribute (and any padding to a 4-byte boundary).
            bb.position(bb.position() + attrLen)
            offset += 4 + alignTo4(attrLen)
            continue
        }
    }
    return null
}

private fun alignTo4(n: Int): Int = (n + 3) and 3.inv()

// ─── I/O ─────────────────────────────────────────────────────────────────

/** UDP STUN client. One probe per [probe] call, fresh source port if
 * not specified, fresh transaction id each time. */
class StunClient(
    private val timeoutMs: Long = 2000,
    private val rng: SecureRandom = SecureRandom(),
) {
    /**
     * Send a single BINDING REQUEST to [server] (host:port string)
     * and parse the response. Returns null on timeout, network
     * error, or malformed response. Does not throw.
     */
    fun probe(server: String, sourcePort: Int = 0): StunMapping? {
        val (host, port) = parseHostPort(server) ?: return null
        val sock = try { DatagramSocket(sourcePort) } catch (_: Exception) { return null }
        try {
            sock.soTimeout = timeoutMs.toInt()
            val txid = randomTxid(rng)
            val req = buildStunBindingRequest(txid)
            val dst = try {
                InetSocketAddress(InetAddress.getByName(host), port)
            } catch (_: Exception) { return null }
            sock.send(DatagramPacket(req, req.size, dst))

            val deadline = System.currentTimeMillis() + timeoutMs
            while (System.currentTimeMillis() < deadline) {
                val buf = ByteArray(2048)
                val pkt = DatagramPacket(buf, buf.size)
                try { sock.receive(pkt) } catch (_: Exception) { return null }
                val data = buf.copyOfRange(0, pkt.length)
                val parsed = parseStunBindingResponse(data, txid)
                if (parsed != null) return parsed
                // If the response wasn't ours (different txid), try
                // once more — but bounded by deadline.
            }
            return null
        } catch (_: Exception) {
            return null
        } finally {
            try { sock.close() } catch (_: Exception) {}
        }
    }

    private fun parseHostPort(s: String): Pair<String, Int>? {
        val i = s.lastIndexOf(':')
        if (i <= 0) return null
        val host = s.substring(0, i)
        val port = s.substring(i + 1).toIntOrNull() ?: return null
        if (port !in 1..65535) return null
        return host to port
    }
}

// ─── Classification ──────────────────────────────────────────────────────

/**
 * Probe each STUN server, observe the mappings, and classify.
 *
 * - All servers see the same external (ip, port) → CONE_PRESERVING
 * if external port equals the local source port we used, else
 * CONE_REMAPPED.
 * - Servers see different external ports for the same source → SYMMETRIC.
 * - No server responded → UNKNOWN.
 *
 * Reuses one source port across all probes to keep the comparison
 * apples-to-apples (matches test 01's behavior).
 */
fun classifyNat(
    servers: List<String>,
    client: StunClient = StunClient(),
): NatClassification {
    if (servers.isEmpty()) {
        return NatClassification(
            NatType.UNKNOWN, null, emptyList(), "no servers supplied")
    }

    // Pick a single source port up front so every probe goes from the
    // same port — that's what makes the cone-vs-symmetric comparison
    // meaningful. Use the kernel-assigned port from a throwaway bind.
    val sourcePort = try {
        DatagramSocket(0).use { s ->
            // s.use closes after use; capture port.
            s.localPort.also { _ -> s.close() }
        }
    } catch (_: Exception) {
        return NatClassification(
            NatType.UNKNOWN, null, emptyList(),
            "could not allocate a source port")
    }

    val obs = mutableListOf<StunMapping>()
    for (srv in servers) {
        val m = client.probe(srv, sourcePort = sourcePort)
        if (m != null) obs += m
    }

    if (obs.isEmpty()) {
        return NatClassification(
            NatType.UNKNOWN, null, emptyList(),
            "no STUN responses received")
    }

    val ips = obs.map { it.externalIp }.toSet()
    val ports = obs.map { it.externalPort }.toSet()
    val externalIp = obs.first().externalIp
    val ipNote = if (ips.size > 1)
        " (multi-WAN? saw external IPs: ${ips.sorted().joinToString(",")})" else ""

    return when {
        ports.size > 1 -> NatClassification(
            NatType.SYMMETRIC, externalIp, obs,
            "external port differs per server${ipNote} — symmetric NAT")
        ports.first() == sourcePort -> NatClassification(
            NatType.CONE_PRESERVING, externalIp, obs,
            "external port == source port${ipNote} — port-preserving cone NAT (or none)")
        else -> NatClassification(
            NatType.CONE_REMAPPED, externalIp, obs,
            "external port consistent but != source${ipNote} — cone but not preserving")
    }
}
