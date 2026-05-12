package com.gutschke.wgrtc.signalling

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class WireFormatTest {

    @Test fun `buildEnrollEnvelope shape matches daemon expectations`() {
        val env = buildEnrollEnvelope(
            dstRoutingId = "deadbeef".repeat(8),
            clientPubBase64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            blobBase64 = "ZmFrZS1ibG9i",
        )
        val obj = env as JsonObject
        assertEquals("OFFER", (obj["type"] as JsonPrimitive).content)
        assertNotNull(obj["dst"])
        val payload = obj["payload"] as JsonObject
        assertEquals("data", (payload["type"] as JsonPrimitive).content)
        assertEquals(false, (payload["reliable"] as JsonPrimitive).content.toBoolean())
        // connectionId begins with dc_ and is mirrored as label
        val cid = (payload["connectionId"] as JsonPrimitive).content
        assertTrue(cid.startsWith("dc_"))
        assertEquals(cid, (payload["label"] as JsonPrimitive).content)
        // metadata fields are what the daemon discriminates on
        val md = payload["metadata"] as JsonObject
        assertEquals(PROTOCOL_VERSION, (md["v"] as JsonPrimitive).content.toInt())
        assertEquals("enroll", (md["kind"] as JsonPrimitive).content)
        assertNotNull(md["client_pub"])
        assertNotNull(md["blob"])
        // SDP envelope must look like a real datachannel offer (the
        // public PeerJS broker rejects anything that doesn't).
        val sdp = (payload["sdp"] as JsonObject)["sdp"] as JsonPrimitive
        assertTrue(sdp.content.contains("m=application"))
        assertTrue(sdp.content.contains("a=ice-ufrag:"))
    }

    @Test fun `buildEnrollEnvelope generates fresh randomness per call`() {
        val a = buildEnrollEnvelope("d".repeat(64), "p", "b") as JsonObject
        val b = buildEnrollEnvelope("d".repeat(64), "p", "b") as JsonObject
        val cidA = (a["payload"] as JsonObject)["connectionId"] as JsonPrimitive
        val cidB = (b["payload"] as JsonObject)["connectionId"] as JsonPrimitive
        // Vanishingly unlikely to collide; if this flakes we have bigger problems.
        assertNotEquals(cidA.content, cidB.content)
    }

    @Test fun `extractEnrollResponse pulls kind+blob from a server reply`() {
        val msg = Json.parseToJsonElement("""
            {
              "type": "OFFER",
              "src": "abc",
              "payload": {
                "type": "data",
                "connectionId": "dc_xyz",
                "label": "dc_xyz",
                "reliable": false,
                "serialization": "binary",
                "sdp": {"sdp": "stub", "type": "offer"},
                "metadata": {
                  "v": 1, "kind": "enroll_ok", "client_pub": "Q", "blob": "Z"
                }
              }
            }
        """.trimIndent())
        val r = extractEnrollResponse(msg)
        assertEquals("enroll_ok", r?.first)
        assertEquals("Z", r?.second)
    }

    @Test fun `extractEnrollResponse rejects non-OFFER`() {
        val msg = Json.parseToJsonElement("""{"type":"OPEN"}""")
        assertNull(extractEnrollResponse(msg))
    }

    @Test fun `extractEnrollResponse rejects wrong kind`() {
        val msg = Json.parseToJsonElement("""
            {"type":"OFFER","payload":{"metadata":{"v":1,"kind":"offer","blob":"x"}}}
        """.trimIndent())
        assertNull(extractEnrollResponse(msg))
    }

    @Test fun `extractEnrollResponse rejects mismatched protocol version`() {
        val msg = Json.parseToJsonElement("""
            {"type":"OFFER","payload":{"metadata":{"v":99,"kind":"enroll_ok","blob":"x"}}}
        """.trimIndent())
        assertNull(extractEnrollResponse(msg))
    }

    @Test fun `EnrollRequestPlain emits its v field even when default`() {
        // Regression for the kotlinx.serialization "drops defaults" trap
        // that bit us before — see the JSON config note in WireFormat.kt.
        val req = EnrollRequestPlain(
            timestamp = 1_700_000_000L,
            tokenCheck = "AA",
            hint = "alice",
            device = "android",
        )
        val s = JSON.encodeToString(EnrollRequestPlain.serializer(), req)
        assertTrue(s.contains("\"v\":1"), "missing v field; encoded: $s")
        assertTrue(s.contains("\"transport\""), "missing client_caps default; encoded: $s")
    }

    @Test fun `EnrollOkPlain decodes a daemon-shaped reply`() {
        val raw = """
            {"v":1,"ts":1700000000,"address":"10.0.0.5/32","allowed_ips":"0.0.0.0/0",
             "keepalive":25,"server_pubkey":"AbCd","server_endpoint_hint":"1.2.3.4:51820",
             "name":"alice"}
        """.trimIndent()
        val ok = JSON.decodeFromString(EnrollOkPlain.serializer(), raw)
        assertEquals("10.0.0.5/32", ok.address)
        assertEquals("1.2.3.4:51820", ok.serverEndpointHint)
        assertEquals("alice", ok.name)
        assertEquals(25, ok.keepalive)
    }

    @Test fun `EnrollErrPlain decodes`() {
        val raw = """{"v":1,"ts":0,"code":"TOKEN_USED","note":"already consumed"}"""
        val err = JSON.decodeFromString(EnrollErrPlain.serializer(), raw)
        assertEquals("TOKEN_USED", err.code)
        assertEquals("already consumed", err.note)
    }

    // ── new (host-side) helpers ───────────────────────────

    @Test fun `extractInboundEnroll pulls src+clientPub+blob from a real envelope`() {
        // Build an envelope the way buildEnrollEnvelope does, then add
        // the broker-set src field (broker server adds it on forwarding).
        val client = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        val env = buildEnrollEnvelope(
            dstRoutingId = "deadbeef".repeat(8),
            clientPubBase64 = client,
            blobBase64 = "ZmFrZS1ibG9i",
        ) as JsonObject
        // Inject src as the broker would.
        val withSrc = JsonObject(env.toMutableMap().apply {
            put("src", JsonPrimitive("cafebabe".repeat(8)))
        })
        val parsed = extractInboundEnroll(withSrc)
        assertNotNull(parsed)
        assertEquals("cafebabe".repeat(8), parsed!!.src)
        assertEquals(client, parsed.clientPubB64)
        assertEquals("ZmFrZS1ibG9i", parsed.blobB64)
    }

    @Test fun `extractInboundEnroll rejects when kind is not enroll`() {
        val msg = Json.parseToJsonElement("""
            {"type":"OFFER","src":"abc","payload":{"metadata":{"v":1,"kind":"signal_wake","client_pub":"x","blob":"y"}}}
        """.trimIndent())
        assertNull(extractInboundEnroll(msg))
    }

    @Test fun `extractInboundEnroll rejects when src is missing`() {
        val msg = Json.parseToJsonElement("""
            {"type":"OFFER","payload":{"metadata":{"v":1,"kind":"enroll","client_pub":"x","blob":"y"}}}
        """.trimIndent())
        assertNull(extractInboundEnroll(msg))
    }

    @Test fun `extractInboundEnroll rejects when client_pub is missing`() {
        val msg = Json.parseToJsonElement("""
            {"type":"OFFER","src":"abc","payload":{"metadata":{"v":1,"kind":"enroll","blob":"y"}}}
        """.trimIndent())
        assertNull(extractInboundEnroll(msg))
    }

    @Test fun `extractInboundEnroll rejects wrong protocol version`() {
        val msg = Json.parseToJsonElement("""
            {"type":"OFFER","src":"abc","payload":{"metadata":{"v":99,"kind":"enroll","client_pub":"x","blob":"y"}}}
        """.trimIndent())
        assertNull(extractInboundEnroll(msg))
    }

    @Test fun `buildEnrollResponseEnvelope shape mirrors daemon`() {
        val env = buildEnrollResponseEnvelope(
            dstRoutingId = "deadbeef".repeat(8),
            kind = "enroll_ok",
            serverPubBase64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            blobBase64 = "ZmFrZQ==",
        ) as JsonObject
        assertEquals("OFFER", (env["type"] as JsonPrimitive).content)
        assertEquals("deadbeef".repeat(8), (env["dst"] as JsonPrimitive).content)
        val md = ((env["payload"] as JsonObject)["metadata"]) as JsonObject
        assertEquals(PROTOCOL_VERSION, (md["v"] as JsonPrimitive).content.toInt())
        assertEquals("enroll_ok", (md["kind"] as JsonPrimitive).content)
        // Response carries server_pub, NOT client_pub.
        assertNotNull(md["server_pub"])
        assertNull(md["client_pub"])
        assertEquals("ZmFrZQ==", (md["blob"] as JsonPrimitive).content)
        // SDP wrapper still present so the public broker accepts it.
        val sdp = ((env["payload"] as JsonObject)["sdp"]) as JsonObject
        assertTrue((sdp["sdp"] as JsonPrimitive).content.contains("m=application"))
    }

    @Test fun `buildEnrollResponseEnvelope accepts enroll_err and rejects junk kinds`() {
        // enroll_err passes
        val errEnv = buildEnrollResponseEnvelope(
            dstRoutingId = "d".repeat(64),
            kind = "enroll_err",
            serverPubBase64 = "p", blobBase64 = "b",
        ) as JsonObject
        val md = ((errEnv["payload"] as JsonObject)["metadata"]) as JsonObject
        assertEquals("enroll_err", (md["kind"] as JsonPrimitive).content)
        // Anything else is a programmer error — fail loud.
        assertThrows(IllegalArgumentException::class.java) {
            buildEnrollResponseEnvelope("d".repeat(64), "wat", "p", "b")
        }
    }
}
