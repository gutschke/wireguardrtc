package com.gutschke.wgrtc.data

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * **Pure-Kotlin ICMPv4 packet helpers.**
 *
 * Build / parse ICMP echo requests + replies for use with
 * Linux's unprivileged `SOCK_DGRAM/IPPROTO_ICMP` "ping socket"
 * (Android exposes the syscall via [android.system.Os]).
 *
 * Kept dependency-free + side-effect-free so the checksum +
 * packet shape can be unit-tested in a plain JVM run. The
 * actual socket I/O lives in [IcmpPinger].
 *
 * **Wire format (RFC 792).**
 * ```
 * 0 1 2 3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Type | Code | Checksum |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Identifier | Sequence Number |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Data ...
 * +-+-+-+-+-+-+-+-+-
 * ```
 *
 * **Linux quirk — identifier rewriting.** When sending via a
 * `SOCK_DGRAM/IPPROTO_ICMP` socket, the kernel REPLACES the
 * identifier field (bytes 4-5) with a per-socket value. The
 * value we write in the outgoing packet is therefore overwritten
 * and shouldn't be trusted; demux replies by sequence number
 * (bytes 6-7) and by the kernel re-routing inbound packets to
 * the originating socket.
 */
object IcmpPacket {

    const val TYPE_ECHO_REPLY: Byte = 0
    const val TYPE_DEST_UNREACHABLE: Byte = 3
    const val TYPE_ECHO_REQUEST: Byte = 8
    const val TYPE_TIME_EXCEEDED: Byte = 11

    const val HEADER_LEN = 8

    /**
     * Build an ICMPv4 echo request packet. The checksum is
     * computed over the full message (header + payload) with the
     * checksum field set to 0 (RFC 1071), then written back into
     * bytes 2-3. The kernel verifies inbound checksums for us
     * but we set the outbound one ourselves — some kernels
     * recompute on send, some don't.
     */
    fun buildEchoRequest(
        identifier: Int,
        sequence: Int,
        payload: ByteArray = DEFAULT_PAYLOAD,
    ): ByteArray {
        require(identifier in 0..0xFFFF) { "identifier out of range: $identifier" }
        require(sequence in 0..0xFFFF) { "sequence out of range: $sequence" }
        val buf = ByteArray(HEADER_LEN + payload.size)
        val bb = ByteBuffer.wrap(buf).order(ByteOrder.BIG_ENDIAN)
        bb.put(TYPE_ECHO_REQUEST)
        bb.put(0) // code
        bb.putShort(0) // checksum placeholder
        bb.putShort(identifier.toShort())
        bb.putShort(sequence.toShort())
        bb.put(payload)
        val csum = computeChecksum(buf)
        bb.position(2)
        bb.putShort(csum.toShort())
        return buf
    }

    /**
     * Parse the start of an ICMPv4 message. Returns null on
     * obviously-malformed input (too-short buffer, etc.).
     * Doesn't verify checksum — the kernel did that.
     */
    fun parse(buf: ByteArray, length: Int = buf.size): IcmpMessage? {
        if (length < HEADER_LEN || length > buf.size) return null
        val bb = ByteBuffer.wrap(buf, 0, length).order(ByteOrder.BIG_ENDIAN)
        val type = bb.get()
        val code = bb.get()
        val checksum = bb.short.toInt() and 0xFFFF
        val identifier = bb.short.toInt() and 0xFFFF
        val sequence = bb.short.toInt() and 0xFFFF
        val payload = ByteArray(length - HEADER_LEN)
        bb.get(payload)
        return IcmpMessage(type, code, checksum, identifier, sequence, payload)
    }

    /**
     * Internet 16-bit one's-complement checksum (RFC 1071).
     * Used for ICMPv4 + IPv4 header checksums (we only need
     * ICMP here — the kernel computes the IP header for
     * SOCK_DGRAM sockets).
     */
    fun computeChecksum(data: ByteArray): Int {
        var sum = 0L
        var i = 0
        while (i + 1 < data.size) {
            val word = ((data[i].toInt() and 0xFF) shl 8) or
                (data[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < data.size) {
            // Odd byte at the end — pad with zero (high byte).
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return (sum.inv().toInt() and 0xFFFF)
    }

    /** The standard 32-byte payload that `ping(1)` uses. Some
     * firewalls / DPI key off payload length; matching the
     * canonical size keeps us from triggering anything weird. */
    val DEFAULT_PAYLOAD: ByteArray = ByteArray(32) { (it and 0xFF).toByte() }
}

data class IcmpMessage(
    val type: Byte,
    val code: Byte,
    val checksum: Int,
    val identifier: Int,
    val sequence: Int,
    val payload: ByteArray,
) {
    val isEchoReply: Boolean get() = type == IcmpPacket.TYPE_ECHO_REPLY && code == 0.toByte()
    val isEchoRequest: Boolean get() = type == IcmpPacket.TYPE_ECHO_REQUEST && code == 0.toByte()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is IcmpMessage) return false
        return type == other.type && code == other.code &&
            checksum == other.checksum && identifier == other.identifier &&
            sequence == other.sequence && payload.contentEquals(other.payload)
    }

    override fun hashCode(): Int {
        var r = type.toInt()
        r = 31 * r + code.toInt()
        r = 31 * r + checksum
        r = 31 * r + identifier
        r = 31 * r + sequence
        r = 31 * r + payload.contentHashCode()
        return r
    }
}
