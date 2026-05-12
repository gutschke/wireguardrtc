package com.gutschke.wgrtc.data

import android.util.Log
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.Inet4Address
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.SocketTimeoutException
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Lightweight HTTP server that delivers a manually-generated
 * wg-quick config to a same-LAN client (e.g. a Chromebook running
 * the Play-Store WireGuard app). Only started when the user
 * explicitly opts in.
 *
 * **Revision history.** The original v1 of this server bound a
 * random 6-letter token in the URL path and served the config as
 * a `Content-Disposition: attachment` once. Real-device testing
 * showed:
 * - The 6-letter token was painful to type from a phone screen
 * onto a Chromebook URL bar.
 * - Chrome refuses to download from a non-HTTPS URL but does
 * consume the GET, so the legitimate fetch was already gone
 * by the time the user noticed.
 * - 60 s TTL was too short for any non-trivial typing path.
 *
 * **Current design.** Serves at the root path on an ephemeral
 * port; the port is the security boundary. The user has to
 * explicitly tap "Serve via HTTP" to start it, and the URL only
 * exists for [ttlMs] (10 minutes by default). Within that window
 * the server happily handles multiple fetches — that means a
 * user who fumbled the first one can just refresh. The threat
 * model survives because:
 *
 * - A LAN attacker would need to be on the same hotspot at the
 * same time as the legitimate fetch, would be racing a fixed
 * URL the user is reading off their phone, and the user
 * watches the WireGuard handshake to confirm the right peer.
 * - Plain HTTP means an in-network attacker could read the
 * payload — but private-network attack surface inside a
 * phone hotspot is small (it's just the user's own devices).
 *
 * Response body is a small HTML page with the config in a `<pre>`
 * block, plus client-side Copy + Download buttons. The download
 * button uses `Blob` + `URL.createObjectURL` so it works even on
 * non-HTTPS contexts where Chrome's secure-download check would
 * otherwise nuke a regular `Content-Disposition: attachment` GET.
 */
class ManualConfigServer(
    private val configText: String,
    private val hostName: String? = null,
    private val ttlMs: Long = 600_000L,
) {
    private val stopped = AtomicBoolean(false)
    private var sock: ServerSocket? = null
    private var acceptThread: Thread? = null
    private var ttlThread: Thread? = null

    @Volatile var url: String? = null
        private set

    @Throws(IOException::class)
    fun start() {
        if (sock != null) return
        val s = ServerSocket(0).apply { soTimeout = 200 /* poll for stop */ }
        sock = s
        val ip = pickServingAddress()
        url = "http://$ip:${s.localPort}/"

        acceptThread = Thread({ acceptLoop(s) }, "manual-config-server").apply {
            isDaemon = true; start()
        }
        ttlThread = Thread({
            try { Thread.sleep(ttlMs) } catch (_: InterruptedException) { return@Thread }
            stop()
        }, "manual-config-ttl").apply { isDaemon = true; start() }
    }

    fun stop() {
        if (!stopped.compareAndSet(false, true)) return
        try { sock?.close() } catch (_: Exception) {}
        sock = null
        ttlThread?.interrupt()
        ttlThread = null
        url = null
    }

    private fun acceptLoop(s: ServerSocket) {
        while (!stopped.get()) {
            val client = try { s.accept() }
                         catch (_: SocketTimeoutException) { continue }
                         catch (_: IOException) { return } // socket closed
            try {
                client.soTimeout = 5_000
                handle(client.getInputStream(), client.getOutputStream())
            } catch (t: Throwable) {
                Log.w("manual-config-server", "handle failed", t)
            } finally {
                try { client.close() } catch (_: Exception) {}
            }
        }
    }

    private fun handle(input: java.io.InputStream, out: OutputStream) {
        val rd = BufferedReader(InputStreamReader(input, Charsets.UTF_8))
        val requestLine = rd.readLine() ?: return
        // Drain headers (we ignore them).
        while (true) { val ln = rd.readLine() ?: break; if (ln.isEmpty()) break }

        val parts = requestLine.split(' ')
        if (parts.size < 2 || parts[0] != "GET") {
            writeHtml(out, 405, "Method Not Allowed",
                "<h1>Method not allowed</h1><p>Use GET.</p>")
            return
        }
        val path = parts[1]
        // Accept root and the favicon path; treat anything else as 404.
        if (path == "/favicon.ico") {
            writeRaw(out, 404, "Not Found", "no", "text/plain")
            return
        }
        if (path != "/" && !path.startsWith("/?")) {
            writeHtml(out, 404, "Not Found",
                "<h1>Not found</h1><p>Open the URL the host is showing on its screen.</p>")
            return
        }
        writeHtml(out, 200, "OK", renderHtml(configText, hostName))
    }

    private fun writeHtml(out: OutputStream, status: Int, statusText: String, html: String) {
        writeRaw(out, status, statusText, html, "text/html; charset=utf-8")
    }

    private fun writeRaw(
        out: OutputStream,
        status: Int,
        statusText: String,
        body: String,
        contentType: String,
    ) {
        val bytes = body.toByteArray(Charsets.UTF_8)
        val sb = StringBuilder()
        sb.append("HTTP/1.0 $status $statusText\r\n")
        sb.append("Content-Type: $contentType\r\n")
        sb.append("Content-Length: ${bytes.size}\r\n")
        sb.append("Cache-Control: no-store\r\n")
        sb.append("Connection: close\r\n")
        sb.append("\r\n")
        out.write(sb.toString().toByteArray(Charsets.UTF_8))
        out.write(bytes)
        out.flush()
    }

    private fun pickServingAddress(): String {
        return try {
            val addrs = NetworkInterface.getNetworkInterfaces().asSequence()
                .filter { it.isUp && !it.isLoopback }
                .flatMap { it.inetAddresses.asSequence() }
                .filterIsInstance<Inet4Address>()
                .filterNot { it.isLoopbackAddress }
                .toList()
            // Prefer 192.168.x.x / 172.16-31.x.x / 10.x.x.x — RFC 1918
            // private space. This rules out cellular's CGNAT addresses
            // (100.64–127.x.x) which exist but don't help a LAN
            // browser reach us. Android's hotspot SoftAP is in the
            // 192.168.49.x range by default, so it'll come out on top.
            addrs.firstOrNull { it.isSiteLocalAddress }?.hostAddress
                ?: addrs.firstOrNull()?.hostAddress
                ?: "0.0.0.0"
        } catch (_: Throwable) { "0.0.0.0" }
    }
}

/**
 * Render the in-memory wg-quick text into a styled HTML page.
 *
 * **Copy-only design.** We previously offered a "Save as wg.conf"
 * button that built a Blob client-side, hoping browsers would let
 * the resulting in-memory download through their secure-download
 * gates. Real-device testing (Chrome, Aug 2026) showed Chrome
 * blocks Blob-URL downloads from http:// origins exactly the same
 * way it blocks server-driven `Content-Disposition` ones — the
 * Downloads-pane "Retry" trick doesn't help because each retry
 * creates a fresh Blob URL.
 *
 * Conclusion: the user has to copy + paste. This page is built
 * around making that as painless as possible:
 *
 * - The config text is rendered into a read-only `<textarea>`.
 * Tapping it auto-selects all, so a user just hits the
 * keyboard's copy shortcut (Ctrl+C / Cmd+C / long-press →
 * Copy on touch).
 * - The "Copy to clipboard" button uses `execCommand('copy')`
 * since `navigator.clipboard` is gated on secure contexts and
 * we're plain HTTP.
 * - The page acknowledges the Chrome download limitation in
 * plain language so users don't waste time trying the
 * non-existent "save" path.
 */
private fun renderHtml(configText: String, hostName: String?): String {
    val escapedText = configText
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    val title = hostName?.let { "Tunnel config — ${escapeHtmlText(it)}" }
        ?: "Tunnel config"
    val fields = WgQuickFields.parse(configText).named()
    val fieldRows = fields.joinToString("\n") { (label, value) ->
        val safeLabel = escapeHtmlText(label)
        val safeValue = escapeHtmlText(value)
        """ <div class="field">
    <label>$safeLabel</label>
    <input type="text" readonly value="$safeValue"
           onclick="this.select()" onfocus="this.select()" />
  </div>"""
    }
    return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>$title</title>
<style>
  :root { color-scheme: light dark; }
  body {
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    max-width: 720px; margin: 24px auto; padding: 0 16px;
    line-height: 1.45;
  }
  h1 { font-size: 1.25rem; margin: 0 0 6px; }
  p.lead { margin: 0 0 12px; opacity: 0.75; }
  textarea#cfg {
    width: 100%; box-sizing: border-box;
    background: #f4f4f5; border: 1px solid #d4d4d8;
    border-radius: 8px; padding: 12px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 0.95rem; line-height: 1.4;
    resize: vertical; min-height: 220px;
    color: inherit;
  }
  @media (prefers-color-scheme: dark) {
    textarea#cfg { background: #1f1f23; border-color: #3f3f46; color: #e4e4e7; }
  }
  button {
    background: #006A6B; color: white; border: 0;
    border-radius: 8px; padding: 12px 22px; font-size: 1.05rem;
    cursor: pointer;
  }
  .actions { display: flex; gap: 8px; margin: 12px 0; flex-wrap: wrap; }
  .toast {
    position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%);
    background: #006A6B; color: white; padding: 10px 20px;
    border-radius: 24px; opacity: 0; transition: opacity 0.2s;
    pointer-events: none;
  }
  .toast.show { opacity: 1; }
  details { margin-top: 20px; opacity: 0.85; }
  details summary { cursor: pointer; padding: 4px 0; }
  details summary:hover { opacity: 1; }
  .note {
    margin-top: 16px; padding: 10px 12px;
    background: rgba(0, 106, 107, 0.08);
    border-left: 3px solid #006A6B;
    border-radius: 4px;
    font-size: 0.92rem;
  }
  h2 {
    font-size: 1.05rem; margin: 32px 0 6px;
    border-top: 1px solid #d4d4d8; padding-top: 18px;
  }
  @media (prefers-color-scheme: dark) {
    h2 { border-top-color: #3f3f46; }
  }
  .field {
    display: flex; align-items: center;
    gap: 12px; margin: 8px 0;
  }
  .field label {
    flex: 0 0 150px;
    font-size: 0.85rem; opacity: 0.75;
  }
  .field input {
    flex: 1; min-width: 0;
    box-sizing: border-box;
    background: #f4f4f5; border: 1px solid #d4d4d8;
    border-radius: 6px; padding: 8px 10px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 0.92rem;
    color: inherit;
  }
  @media (prefers-color-scheme: dark) {
    .field input { background: #1f1f23; border-color: #3f3f46; color: #e4e4e7; }
  }
  @media (max-width: 500px) {
    .field { flex-direction: column; align-items: stretch; gap: 4px; }
    .field label { flex: none; }
  }
</style>
</head>
<body>
<h1>WireGuard tunnel configuration</h1>
<p class="lead">
  Tap the box to select all, then copy. Paste the text into your
  WireGuard client to import the tunnel.
</p>
<textarea id="cfg" readonly spellcheck="false" onclick="this.select()" onfocus="this.select()">$escapedText</textarea>
<div class="actions">
  <button onclick="copyCfg()">Copy to clipboard</button>
</div>
<div id="toast" class="toast">Copied</div>

<h2>Or — copy field by field</h2>
<p style="opacity:0.75;font-size:0.92rem;margin:0 0 12px;">
  ChromeOS and some routers ask for each WireGuard field separately
  rather than a paste-the-block import. Tap any field to select
  it, then copy.
</p>
$fieldRows
<details open>
<summary>How to import this on the joining device</summary>
<ul>
  <li><strong>ChromeOS:</strong> Settings → Network → Add connection →
      Add WireGuard. Click the import / paste option, then paste.</li>
  <li><strong>Android / iOS WireGuard app:</strong> tap +, choose
      "Create from clipboard" after copying.</li>
  <li><strong>Linux / macOS / Windows:</strong> paste into a file named
      <code>wg.conf</code> and import via the WireGuard app, or run
      <code>wg-quick up ./wg.conf</code>.</li>
</ul>
<p>Once imported, connect. WireGuard's first handshake takes a
   couple of seconds. After that you'll be able to reach the host
   device at the IP shown in the <code>Endpoint</code> line above.</p>
</details>
<div class="note">
  Chrome blocks downloads from non-HTTPS pages, so we don't try.
  If the copy button doesn't work in your browser, manually
  select the text in the box above and copy it (Ctrl+C / Cmd+C,
  or long-press → Copy on touch).
</div>
<script>
function toast(msg) {
  var el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.add('show');
  setTimeout(function () { el.classList.remove('show'); }, 1400);
}
function copyCfg() {
  var ta = document.getElementById('cfg');
  ta.select();
  // navigator.clipboard requires secure context, which we won't be
  // on plain HTTP. execCommand('copy') still works in current
  // browsers when called from a user-gesture handler.
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(ta.value).then(
      function () { toast('Copied'); },
      function () { fallbackCopy(ta); }
    );
    return;
  }
  fallbackCopy(ta);
}
function fallbackCopy(ta) {
  try {
    var ok = document.execCommand('copy');
    toast(ok ? 'Copied' : 'Press Ctrl+C / ⌘+C to copy');
  } catch (e) {
    toast('Press Ctrl+C / ⌘+C to copy');
  }
}
</script>
</body>
</html>"""
}

private fun escapeHtmlText(s: String): String = s
    .replace("&", "&amp;")
    .replace("<", "&lt;")
    .replace(">", "&gt;")
