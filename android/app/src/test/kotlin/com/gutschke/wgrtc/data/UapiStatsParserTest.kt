package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Behaviour of [UapiStatsParser]: turn wireguard-go's IpcGet UAPI
 * dump into a [UapiStats] object the host-mode UI can consume.
 *
 * The format is line-oriented `key=value`, terminated by an empty
 * line. Peer sections start with `public_key=<hex>`; all subsequent
 * fields up to the next `public_key=` (or the document end) belong
 * to that peer. Unrecognised keys are ignored.
 *
 * Pubkey hex → base64 conversion is the parser's responsibility so
 * the status line (which keys [PeerStats] by base64) lines up
 * regardless of which mode generated the snapshot.
 */
class UapiStatsParserTest {

    @Test
    fun `parses interface fields`() {
        val sample = """
            private_key=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
            listen_port=51820
            fwmark=0
        """.trimIndent() + "\n"
        val s = UapiStatsParser.parse(sample)
        assertEquals(51820, s.listenPort)
        assertTrue(s.peers.isEmpty())
    }

    @Test
    fun `parses a single peer's bytes and handshake epoch`() {
        // public_key bytes 0x01..0x20 encoded hex → standard-base64.
        val pubHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        val sample = """
            private_key=ff${"00".repeat(31)}
            listen_port=51820
            public_key=$pubHex
            allowed_ip=10.99.0.2/32
            endpoint=192.0.2.1:54321
            last_handshake_time_sec=1715000000
            last_handshake_time_nsec=750000000
            tx_bytes=1024
            rx_bytes=2048
            persistent_keepalive_interval=0
        """.trimIndent() + "\n"
        val s = UapiStatsParser.parse(sample)
        val peer = s.peers.values.single()
        // 1715000000 sec + 0.75 sec worth of nsec → 1715000000750 ms
        assertEquals(1715000000750L, peer.lastHandshakeEpochMs)
        assertEquals(2048L, peer.rxBytes)
        assertEquals(1024L, peer.txBytes)
        // Hex-to-base64 verification.
        val pubBase64 = java.util.Base64.getEncoder().encodeToString(
            ByteArray(32) { (it + 1).toByte() })
        assertTrue(s.peers.containsKey(pubBase64),
            "expected key $pubBase64, got ${s.peers.keys}")
    }

    @Test
    fun `last_handshake_time_sec=0 maps to null lastHandshakeEpochMs`() {
        // Per WG convention — kernel reports 0 for "never".
        val pubHex = "ab".repeat(32)
        val sample = """
            private_key=00${"00".repeat(31)}
            listen_port=51820
            public_key=$pubHex
            last_handshake_time_sec=0
            last_handshake_time_nsec=0
            tx_bytes=0
            rx_bytes=0
        """.trimIndent() + "\n"
        val s = UapiStatsParser.parse(sample)
        assertNull(s.peers.values.single().lastHandshakeEpochMs)
    }

    @Test
    fun `multiple peers are split correctly`() {
        val p1 = "01".repeat(32)
        val p2 = "02".repeat(32)
        val sample = """
            private_key=ff${"00".repeat(31)}
            listen_port=51820
            public_key=$p1
            allowed_ip=10.99.0.2/32
            tx_bytes=10
            rx_bytes=20
            last_handshake_time_sec=100
            last_handshake_time_nsec=0
            public_key=$p2
            allowed_ip=10.99.0.3/32
            tx_bytes=30
            rx_bytes=40
            last_handshake_time_sec=0
            last_handshake_time_nsec=0
        """.trimIndent() + "\n"
        val s = UapiStatsParser.parse(sample)
        assertEquals(2, s.peers.size)
        val p1Base64 = java.util.Base64.getEncoder().encodeToString(ByteArray(32) { 1.toByte() })
        val p2Base64 = java.util.Base64.getEncoder().encodeToString(ByteArray(32) { 2.toByte() })
        val a = s.peers[p1Base64]!!
        val b = s.peers[p2Base64]!!
        assertEquals(20L, a.rxBytes)
        assertEquals(40L, b.rxBytes)
        assertEquals(100_000L, a.lastHandshakeEpochMs)
        assertNull(b.lastHandshakeEpochMs)
    }

    @Test
    fun `total rx tx are aggregated across peers`() {
        val p1 = "01".repeat(32)
        val p2 = "02".repeat(32)
        val sample = """
            private_key=ff${"00".repeat(31)}
            public_key=$p1
            tx_bytes=100
            rx_bytes=200
            last_handshake_time_sec=0
            last_handshake_time_nsec=0
            public_key=$p2
            tx_bytes=300
            rx_bytes=400
            last_handshake_time_sec=0
            last_handshake_time_nsec=0
        """.trimIndent() + "\n"
        val s = UapiStatsParser.parse(sample)
        assertEquals(400L, s.totalTxBytes)
        assertEquals(600L, s.totalRxBytes)
    }

    @Test
    fun `mostRecentHandshakeEpochMs returns the largest non-null peer value`() {
        val p1 = "01".repeat(32)
        val p2 = "02".repeat(32)
        val sample = """
            public_key=$p1
            last_handshake_time_sec=1000
            last_handshake_time_nsec=0
            tx_bytes=0
            rx_bytes=0
            public_key=$p2
            last_handshake_time_sec=2000
            last_handshake_time_nsec=0
            tx_bytes=0
            rx_bytes=0
        """.trimIndent() + "\n"
        val s = UapiStatsParser.parse(sample)
        assertEquals(2_000_000L, s.mostRecentHandshakeEpochMs)
    }

    @Test
    fun `mostRecentHandshakeEpochMs is null when no peer has handshaken`() {
        val pub = "01".repeat(32)
        val sample = """
            public_key=$pub
            last_handshake_time_sec=0
            last_handshake_time_nsec=0
            tx_bytes=0
            rx_bytes=0
        """.trimIndent() + "\n"
        val s = UapiStatsParser.parse(sample)
        assertNull(s.mostRecentHandshakeEpochMs)
    }

    @Test
    fun `errno=0 line is ignored`() {
        // wireguard-go terminates IpcGet output with an `errno=0` line
        // before the final blank line; the parser must not interpret
        // that as a stat.
        val sample = """
            listen_port=51820
            errno=0
        """.trimIndent() + "\n"
        val s = UapiStatsParser.parse(sample)
        assertEquals(51820, s.listenPort)
    }

    @Test
    fun `tolerates Windows line endings and blank lines`() {
        val pubHex = "01".repeat(32)
        val sample = "private_key=ff${"00".repeat(31)}\r\nlisten_port=51820\r\n\r\n" +
            "public_key=$pubHex\r\ntx_bytes=10\r\nrx_bytes=20\r\n" +
            "last_handshake_time_sec=0\r\nlast_handshake_time_nsec=0\r\n"
        val s = UapiStatsParser.parse(sample)
        assertEquals(51820, s.listenPort)
        assertEquals(1, s.peers.size)
    }

    @Test
    fun `empty input returns empty stats`() {
        val s = UapiStatsParser.parse("")
        assertNull(s.listenPort)
        assertTrue(s.peers.isEmpty())
        assertEquals(0L, s.totalTxBytes)
        assertEquals(0L, s.totalRxBytes)
        assertNull(s.mostRecentHandshakeEpochMs)
    }
}
