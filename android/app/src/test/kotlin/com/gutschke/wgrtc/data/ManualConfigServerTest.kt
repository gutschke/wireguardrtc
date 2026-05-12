package com.gutschke.wgrtc.data

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.HttpURLConnection
import java.net.URL

class ManualConfigServerTest {

    private val sampleConfig = """
        [Interface]
        PrivateKey = abcdef
        Address = 10.99.0.2/32

        [Peer]
        PublicKey = ghijkl
        Endpoint = 1.2.3.4:51820
        AllowedIPs = 10.99.0.0/24
    """.trimIndent()

    @Test fun `serves an HTML page containing the config text`() {
        val srv = ManualConfigServer(sampleConfig, ttlMs = 60_000)
        srv.start()
        try {
            val port = URL(srv.url).port
            val (status, body, contentType) = httpGet("http://127.0.0.1:$port/")
            assertEquals(200, status)
            assertTrue(contentType?.startsWith("text/html") == true,
                "expected text/html, got $contentType")
            // The config text shows up in the page (escaped, but the
            // distinctive lines still match unescaped because they
            // contain no <, >, or & characters).
            assertTrue(body.contains("PrivateKey = abcdef"))
            assertTrue(body.contains("Endpoint = 1.2.3.4:51820"))
            assertTrue(body.contains("AllowedIPs = 10.99.0.0/24"))
            // Page chrome present.
            assertTrue(body.contains("<title>"))
            assertTrue(body.contains("Copy to clipboard"))
            // Selectable textarea (not <pre>) so users without
            // clipboard JS can fall back to manual select-all.
            assertTrue(body.contains("<textarea id=\"cfg\""))
        } finally {
            srv.stop()
        }
    }

    @Test fun `does not advertise a Save button`() {
        // Regression guard: Chrome (Aug 2026) blocks Blob-driven
        // downloads from http:// origins. We removed the Save
        // button to stop frustrating users; this test guards
        // against accidentally re-introducing it.
        val srv = ManualConfigServer(sampleConfig, ttlMs = 60_000)
        srv.start()
        try {
            val port = URL(srv.url).port
            val (_, body, _) = httpGet("http://127.0.0.1:$port/")
            assertTrue(!body.contains("Save as wg.conf"),
                "Save button must not appear — Chrome blocks the download.")
            assertTrue(!body.contains("downloadCfg"),
                "Save handler must not appear either.")
        } finally {
            srv.stop()
        }
    }

    @Test fun `multiple fetches work within the TTL window`() {
        // The new contract: multi-fetch during TTL. Tests that an
        // initial fetch followed by a second one both succeed —
        // a regression from the previous v1 single-shot behaviour
        // would have the second request return 410.
        val srv = ManualConfigServer(sampleConfig, ttlMs = 60_000)
        srv.start()
        try {
            val port = URL(srv.url).port
            val first = httpGet("http://127.0.0.1:$port/")
            assertEquals(200, first.first)
            val second = httpGet("http://127.0.0.1:$port/")
            assertEquals(200, second.first)
            assertEquals(first.second, second.second,
                "same body across fetches")
        } finally {
            srv.stop()
        }
    }

    @Test fun `unknown path returns 404 without leaking the config`() {
        val srv = ManualConfigServer(sampleConfig, ttlMs = 60_000)
        srv.start()
        try {
            val port = URL(srv.url).port
            val (status, body, _) = httpGet("http://127.0.0.1:$port/secrets")
            assertEquals(404, status)
            assertTrue(!body.contains("PrivateKey"),
                "404 must not leak config text")
        } finally {
            srv.stop()
        }
    }

    @Test fun `favicon path returns a tiny 404 instead of the page`() {
        // Browsers fetch /favicon.ico unprompted; we don't want to
        // serve them a full HTML page for that.
        val srv = ManualConfigServer(sampleConfig, ttlMs = 60_000)
        srv.start()
        try {
            val port = URL(srv.url).port
            val (status, body, ct) = httpGet("http://127.0.0.1:$port/favicon.ico")
            assertEquals(404, status)
            assertTrue(body.length < 100)
            assertTrue(ct?.startsWith("text/plain") == true)
        } finally {
            srv.stop()
        }
    }

    @Test fun `stop is idempotent and clears the URL`() {
        val srv = ManualConfigServer(sampleConfig)
        srv.start()
        assertTrue(srv.url != null)
        srv.stop()
        srv.stop() // no exception
        assertNull(srv.url)
    }

    @Test fun `URL has no path token`() {
        // Regression guard: previously the URL was /c/<6-char-token>.
        // Now it should serve at root, no token, port-only security.
        val srv = ManualConfigServer(sampleConfig, ttlMs = 60_000)
        srv.start()
        try {
            val u = URL(srv.url)
            // Path is "/" at root; URL parser gives empty string.
            assertTrue(u.path.isEmpty() || u.path == "/",
                "expected root path, got '${u.path}'")
        } finally {
            srv.stop()
        }
    }

    private fun httpGet(url: String): Triple<Int, String, String?> {
        val u = URL(url)
        val conn = u.openConnection() as HttpURLConnection
        conn.connectTimeout = 2_000
        conn.readTimeout = 2_000
        return try {
            conn.requestMethod = "GET"
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val body = stream?.bufferedReader(Charsets.UTF_8)?.readText() ?: ""
            Triple(code, body, conn.contentType)
        } finally {
            conn.disconnect()
        }
    }
}
