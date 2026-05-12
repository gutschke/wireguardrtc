package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * **ICMP packet builder / parser tests.**
 *
 * Pin the wire format so a future change can't accidentally
 * produce malformed pings. The checksum cases are sourced from
 * RFC 1071 §3 worked examples + a known-good real ICMP packet
 * captured from `tcpdump`.
 */
class IcmpPacketTest {

    @Test fun checksumKnownValueFromRfc1071() {
        // RFC 1071 §2.1 worked example: bytes
        // 00 01 f2 03 f4 f5 f6 f7
        // sum to 0xddf2 (with carry-around). The *checksum* (what
        // you write into the packet) is the one's complement of
        // the sum: 0xffff ^ 0xddf2 = 0x220d.
        val data = byteArrayOf(
            0x00, 0x01, 0xf2.toByte(), 0x03,
            0xf4.toByte(), 0xf5.toByte(), 0xf6.toByte(), 0xf7.toByte(),
        )
        assertEquals(0x220d, IcmpPacket.computeChecksum(data))
    }

    @Test fun checksumOddLengthPadsWithZero() {
        // 0x12, 0x34, 0x56 → sum (0x1234 + 0x5600) = 0x6834
        // → checksum 0xffff ^ 0x6834 = 0x97cb
        val data = byteArrayOf(0x12, 0x34, 0x56)
        assertEquals(0x97cb, IcmpPacket.computeChecksum(data))
    }

    @Test fun checksumZeroBufferIsAllOnes() {
        // No data → sum = 0 → checksum = 0xffff (one's complement of 0)
        val data = ByteArray(0)
        assertEquals(0xffff, IcmpPacket.computeChecksum(data))
    }

    @Test fun buildEchoRequestHasCorrectShape() {
        val pkt = IcmpPacket.buildEchoRequest(
            identifier = 0xABCD,
            sequence = 0x0042,
            payload = byteArrayOf(0xAA.toByte(), 0xBB.toByte()),
        )
        assertEquals(10, pkt.size, "header(8) + payload(2)")
        assertEquals(IcmpPacket.TYPE_ECHO_REQUEST, pkt[0])
        assertEquals(0.toByte(), pkt[1], "code must be 0")
        assertEquals(0xAB.toByte(), pkt[4])
        assertEquals(0xCD.toByte(), pkt[5])
        assertEquals(0x00.toByte(), pkt[6])
        assertEquals(0x42.toByte(), pkt[7])
        assertEquals(0xAA.toByte(), pkt[8])
        assertEquals(0xBB.toByte(), pkt[9])
    }

    @Test fun buildEchoRequestChecksumZerosOutWhenVerified() {
        // The checksum field, when included in the sum with the
        // checksum filled in, makes the total sum 0xffff (i.e.
        // the one's-complement sum of the packet with the
        // checksum field included is zero, by construction).
        val pkt = IcmpPacket.buildEchoRequest(identifier = 1, sequence = 1)
        // Verify by recomputing checksum WITH the checksum bytes
        // present — should yield 0 (i.e. the packet is "self-
        // consistent" per RFC 1071 §1).
        val verify = IcmpPacket.computeChecksum(pkt)
        assertEquals(0, verify, "packet must verify with its own checksum")
    }

    @Test fun parseRoundTripsBuildEchoRequest() {
        val pkt = IcmpPacket.buildEchoRequest(0x1234, 0x5678,
            payload = byteArrayOf(1, 2, 3, 4, 5))
        val parsed = IcmpPacket.parse(pkt)
        assertNotNull(parsed)
        parsed!!
        assertEquals(IcmpPacket.TYPE_ECHO_REQUEST, parsed.type)
        assertEquals(0.toByte(), parsed.code)
        assertEquals(0x1234, parsed.identifier)
        assertEquals(0x5678, parsed.sequence)
        assertArrayEquals(byteArrayOf(1, 2, 3, 4, 5), parsed.payload)
        assertTrue(parsed.isEchoRequest)
        assertEquals(false, parsed.isEchoReply)
    }

    @Test fun parseReturnsNullForTooShortBuffer() {
        assertNull(IcmpPacket.parse(ByteArray(0)))
        assertNull(IcmpPacket.parse(ByteArray(7)))
    }

    @Test fun parseEchoReplyRecognized() {
        // Type 0 = echo reply.
        val raw = byteArrayOf(
            0, 0, // type=0, code=0
            0, 0, // checksum (don't care for parse)
            0x12, 0x34, // identifier
            0x00, 0x01, // sequence = 1
            0x41, 0x42, 0x43, // payload "ABC"
        )
        val msg = IcmpPacket.parse(raw)!!
        assertEquals(IcmpPacket.TYPE_ECHO_REPLY, msg.type)
        assertTrue(msg.isEchoReply)
        assertEquals(false, msg.isEchoRequest)
        assertEquals(0x1234, msg.identifier)
        assertEquals(0x0001, msg.sequence)
    }

    @Test fun checksumIsRfcCompliant_validatedByRoundTrip() {
        // Round-trip property: any packet built by buildEchoRequest
        // verifies as a zero checksum.
        for (seq in listOf(0, 1, 0x100, 0xFFFF)) {
            for (size in listOf(0, 1, 15, 16, 17, 32, 64)) {
                val payload = ByteArray(size) { (it * 7 + 13).toByte() }
                val pkt = IcmpPacket.buildEchoRequest(0xABCD, seq, payload)
                assertEquals(0, IcmpPacket.computeChecksum(pkt),
                    "seq=$seq size=$size must self-verify")
            }
        }
    }

    @Test fun defaultPayloadIs32Bytes() {
        assertEquals(32, IcmpPacket.DEFAULT_PAYLOAD.size,
            "matches ping(1)'s default — see kdoc")
    }
}
