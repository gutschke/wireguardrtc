package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.Base64

class HostModeUapiTest {

    private val privKey32 = ByteArray(32) { (it + 1).toByte() }
    private val privB64 = Base64.getEncoder().encodeToString(privKey32)
    private val privHex = privKey32.joinToString("") { "%02x".format(it) }

    private val peer1Key = ByteArray(32) { (0xaa).toByte() }
    private val peer1B64 = Base64.getEncoder().encodeToString(peer1Key)
    private val peer1Hex = "aa".repeat(32)

    private val peer2Key = ByteArray(32) { (0x55).toByte() }
    private val peer2B64 = Base64.getEncoder().encodeToString(peer2Key)
    private val peer2Hex = "55".repeat(32)

    @Test
    fun `private_key + listen_port emitted with no peers`() {
        val out = HostModeUapi.render(privB64, listenPort = 51820, peers = emptyList())
        assertEquals("private_key=$privHex\nlisten_port=51820\n", out)
    }

    @Test
    fun `peers emit hex pubkey + allowed_ip in order`() {
        val out = HostModeUapi.render(
            privateKeyB64 = privB64,
            listenPort = 51820,
            peers = listOf(
                HostModeUapi.Peer(peer1B64, "10.99.0.2/32"),
                HostModeUapi.Peer(peer2B64, "10.99.0.3/32"),
            ),
        )
        val expected = buildString {
            append("private_key=$privHex\n")
            append("listen_port=51820\n")
            append("public_key=$peer1Hex\n")
            append("allowed_ip=10.99.0.2/32\n")
            append("public_key=$peer2Hex\n")
            append("allowed_ip=10.99.0.3/32\n")
        }
        assertEquals(expected, out)
    }

    @Test
    fun `hex output is lowercase and 64 chars per key`() {
        val out = HostModeUapi.render(
            privateKeyB64 = privB64,
            listenPort = 1,
            peers = listOf(HostModeUapi.Peer(peer1B64, "10.0.0.1/32")),
        )
        // Pubkey hex is exactly 64 chars (32 bytes * 2).
        val pubkeyLine = out.lines().first { it.startsWith("public_key=") }
        assertEquals(64, pubkeyLine.removePrefix("public_key=").length)
        assertEquals(pubkeyLine.lowercase(), pubkeyLine)
    }

    @Test
    fun `output ends with newline`() {
        val out = HostModeUapi.render(privB64, 51820, emptyList())
        assertTrue(out.endsWith("\n"))
    }

    @Test
    fun `listen_port appears verbatim`() {
        val out = HostModeUapi.render(privB64, 12345, emptyList())
        assertTrue(out.contains("listen_port=12345\n"))
    }

    @Test
    fun `invalid base64 surface as IllegalArgumentException`() {
        // Sanity check that base64 decoding errors propagate (the
        // caller is supposed to validate; we don't want a silent
        // empty key in the UAPI output).
        try {
            HostModeUapi.render("not!valid!base64!", 51820, emptyList())
            error("expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) { /* expected */ }
    }
}
