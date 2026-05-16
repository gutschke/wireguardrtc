# Transport Obfuscation — Design Document

**Status:** Draft v3 (2026-05-16) — committed design pending implementation. This document defines the obfuscation layer for v0.3.x — what shape it takes, what we build vs. import, and how it coexists with the existing direct-WG mode.
**Author:** wgrtc developers (this doc lives alongside the code).
**Scope:** Adding HTTPS-mimicry transports (MASQUE and WebSocket-over-TLS) to wgrtc as additional carriers for WireGuard packets, so users on networks that block or fingerprint plain WG/UDP can keep their tunnels up.

v3 incorporates two rounds of critical review: v1 (initial draft → architectural redesign) and v2 (verifying library APIs, closing cross-section inconsistencies, committing to open trade-offs). v1 + v2 are preserved in git history.

This is a living document.


## 1. Why this is worth doing

1. **Plain WireGuard is detectable.** WG's handshake message format is well-known (148/92-byte init/response, distinctive first-byte type field). DPI engines flag it trivially.
2. **Some networks block UDP entirely.** Corporate Wi-Fi, hotel guest networks, conference networks. Today wgrtc has no answer beyond "use a different network."
3. **QUIC is increasingly actively blocked.** Russia's TSPU drops QUIC by version-field fingerprint without further inspection; China's GFW parses QUIC Initial frames (Initial keys are derivable from the Destination Connection ID per RFC 9001) and applies heuristic filtering on SNI / version selection. We design assuming QUIC may be blocked outright in some networks — WSS fallback is the *expected* path on those networks, not an exception.
4. **State-level censorship is real and growing.** The threat model is no longer "weird corporate firewall" — it's active probing by network observers who categorize traffic as "looks like a VPN, drop." A perfectly-shaped HTTPS connection survives this; bare WG does not.
5. **wgrtc's existing direct-WG mode is still the right answer for most users on most networks.** This work doesn't replace it — it adds another mode for the cases where direct WG fails.


## 2. Working principles

### 2.1 Pluralism

wgrtc supports multiple connection modes per-tunnel, not per-deployment. Each tunnel has a list of transports the host accepts, advertised at pairing time. A single daemon can host legacy-WG, direct-roaming-WG, and MASQUE/WSS tunnels simultaneously. Migration between modes is a per-tunnel re-pair, not a daemon reinstall.

### 2.2 Kernel WireGuard remains the default on the daemon

Per CLAUDE.md invariants, the Linux daemon runs kernel WG. Obfuscation modes add a userspace relay process that mediates between QUIC/WSS on the outside and kernel WG on the inside via a per-peer localhost UDP socket. The kernel WG data path is preserved. Userspace WireGuard is **not** introduced on the daemon side.

The Android side is already fully userspace (wireguard-go via cgo, gvisor netstack), so no equivalent rearchitecture is needed there.

### 2.3 Auto-discovery and fallback are mandatory

Users cannot reasonably answer "is QUIC blocked on this network?" The transport layer probes at connection time and falls back automatically. Per-tunnel configuration says **what transports the host supports**, never **what transport the joiner must use**. The joiner picks at runtime based on what works.

### 2.4 Look like a real HTTPS site, fail like one

The MASQUE/WSS listener serves uniformly-styled decoy content for unauthenticated requests. A direct probe from a censor must look like it hit a small, mostly-empty real site — not "VPN endpoint detected." All wgrtc deployments serve **identical default decoy content** (§13), so deployments are not distinguishable from each other by the decoy.

### 2.5 Reuse existing trust where applicable; separate where not

Wormhole pairing establishes a shared secret. We use it where appropriate (per-peer auth, TLS fingerprint pinning). We do **not** reuse the WG private key as the root of the URL-token derivation chain — a separate, persisted, rotatable secret lives in `/etc/wireguardrtc/` (§7).

### 2.6 Symmetric protocol support on both platforms

Both Android and the daemon implement both **client and server** sides of both MASQUE and WSS. Either platform can accept incoming obfuscated connections or initiate outgoing ones. Reasons:
1. **Interop testing** — cross-platform regressions are easier to spot when daemon-as-joiner can dial Android-as-host through the same code paths daemon-as-host serves on the receiving end.
2. **Cascading tunnels** (D3 shipped; D4 generalizes) — daemon-as-joiner is a real use case.
3. **Phone-as-server is real** — HostModeBackend is shipped. Hosting from a hostile network is exactly when obfuscation matters.

Asymmetries that remain unavoidable are flagged per-section (WSS hole-punching impossibility in §10.5, FGS notification on Android-as-MASQUE-server in §12.4).


## 3. Threat model

| Adversary capability | Direct WG | MASQUE | WSS |
|---|---|---|---|
| Passive observation of packet headers | DETECTABLE (WG well-known) | MIMICRY (QUIC pattern) | MIMICRY (TLS pattern) |
| Active QUIC fingerprinting (version-field, Initial pattern) | n/a | **VULNERABLE** (TSPU/GFW drop QUIC) | n/a |
| TLS-handshake fingerprinting (JA3/JA4) | n/a | Partial leak (Go stdlib shape) | Same |
| Active probing of listener with HTTP requests | n/a | Decoy site + uniform 404s | Same |
| Active probing with crafted CONNECT-UDP/WS requests | n/a | URL token gate | Same |
| Statistical traffic analysis (packet sizes/timing) | Fingerprintable | Partial mitigation | Partial |
| UDP/443 blocked | **FAILS** | **FAILS** → WSS fallback | Survives (TCP) |
| QUIC blocked but UDP allowed | Works | **FAILS** → WSS fallback | Survives |
| TLS allowed | n/a | n/a | Survives |

We do **not** defend against:
- Endpoint compromise (kernel rootkit on either peer).
- Active MITM with a CA the joiner trusts (out-of-scope; mitigation is fingerprint pinning).
- Long-horizon statistical analysis by state actors with full traffic capture (ceiling problem; partial mitigation in future padding work).
- TLS-handshake fingerprinting via JA3/JA4 (acknowledged limitation; uTLS-for-QUIC is future work).
- Cloudflare or other CDN's voluntary cooperation with a state observer.


## 4. Architecture

### 4.1 Three connection modes

| Mode | Outer transport | Best for | Daemon-side data path |
|---|---|---|---|
| **`direct`** (existing) | Raw UDP, hole-punched | Most users, most networks | Kernel WG |
| **`masque`** (new) | QUIC + HTTP/3 + CONNECT-UDP (RFC 9298) | DPI-hostile networks; hosts with reachable UDP/443 | Kernel WG via localhost relay |
| **`wss`** (new) | TLS + WebSocket binary frames (RFC 6455) | UDP-blocked networks; reverse-proxy-fronted hosts | Kernel WG via localhost relay |

A single tunnel can advertise multiple transports simultaneously. The joiner picks one at connect time via §9.

### 4.2 Per-tunnel transport advertisement

The host's `SasEnrollInfo` payload (already extensible per V6.3) gains an `endpoints` field with typed entries plus an envelope version:

```json
{
  "endpoints_version": 1,
  "endpoints": [
    {"type": "wg", "host": "203.0.113.5", "port": 51820, "priority": 100},
    {"type": "wg", "host": "2001:db8::5", "port": 51820, "priority": 110},
    {"type": "masque", "host": "203.0.113.5", "port": 443, "sni": "www.example.com", "fingerprint": "sha256-…", "priority": 50},
    {"type": "masque", "host": "vpn.example.com", "port": 443, "sni": "vpn.example.com", "ca": "public", "priority": 60},
    {"type": "wss", "url": "wss://proxy.example.com/wgrtc/<token>", "ca": "public", "priority": 30}
  ]
}
```

- `priority` is the host's preference for the joiner (higher is preferred). The joiner uses this as a tiebreaker after transport-class ordering (§9).
- `endpoints_version` lets future schema changes mark themselves explicit. A joiner that sees an unknown version logs a warning and falls back to the `wgEndpoint` field as if obfuscation weren't supported. (Older joiners that don't read `endpoints` at all also degrade safely — they use the existing `wgEndpoint` string.)
- `fingerprint` pins a self-signed cert; `ca: "public"` means "use system root CAs and validate hostname." Per-entry; both can appear in the same endpoint list for the same host (one TLS-pinned endpoint + one CA-validated endpoint).
- `sni` should be DNS-resolvable to *something* (preferably a real popular service apex like a major CDN) to defeat SNI-validation-style drops. The relay accepts any SNI (§5.4); the value is chosen for mimicry, not routing. Static-IP deployments with their own public hostname should put that hostname here.
- The `wss` URL embeds the per-peer URL token (§7); the same token is also delivered as the canonical `urlToken` field (§14.1) so the joiner can construct alternate `wss://` URLs (different reverse-proxy front, etc.) if needed.

### 4.3 Transport plugin abstraction

On both daemon and Android sides, a single `Transport` interface that:
- accepts WG-protocol bytes on one end and emits them at the other,
- handles its own connection lifecycle (handshake, keepalive, teardown),
- exposes a "ready / not ready / failed" state for the auto-discovery layer.

Two implementations: `MasqueTransport` and `WssTransport`. They share envelope encryption, peer auth, MTU accounting, and lifecycle scaffolding via a common base. Plain `direct` mode bypasses this abstraction (it talks directly to kernel WG / wireguard-go via the existing path).


## 5. Transport: MASQUE (CONNECT-UDP)

### 5.1 Why CONNECT-UDP, not CONNECT-IP

RFC 9298 (CONNECT-UDP) tunnels a single UDP flow per HTTP request. RFC 9484 (CONNECT-IP) tunnels arbitrary IP. WG is intrinsically UDP, so CONNECT-UDP is sufficient. Less per-packet overhead, simpler integration, no need to parse or filter inner IP.

### 5.2 URI template

```
https://<host>:<port>/<peer-token>/wgrtc/v1/cu/{target_host}/{target_port}/
```

Where `<peer-token>` is a 22-character base64url-encoded HMAC (§7).

The `{target_host}/{target_port}` template parameters are populated with sentinel values (e.g., `127.0.0.1` and the WG listen port number), but they are **not actually used for routing**. The relay's HTTP handler extracts the template variables but discards them; it then calls `masque-go`'s `Proxy.ProxyConnectedSocket(req, socket)` API to bind the CONNECT-UDP session to a per-peer pre-allocated localhost UDP socket (§11.2). The `Proxy.Proxy(req)` API would do its own DNS resolution and `DialUDP` — we do not call it.

On the joiner (client) side, `masque-go`'s `Client.DialAddr` always populates the URI template with the real target. To route through our relay's sentinel logic, the joiner constructs the HTTP/3 request manually using `quic-go`'s HTTP/3 client primitives, putting the sentinel values directly into the URL. This is ~100 lines of code on the client side, not a single library call. The joiner-side estimate in §18 / Phase 2 accounts for this.

This decouples wire-level URI conformance (which a strict MASQUE-conformant CDN/intermediary would enforce) from internal packet routing.

### 5.3 Libraries

- `github.com/quic-go/quic-go` — QUIC v1, MIT. Pin to a tagged release; vendor via `go mod vendor`.
- `github.com/quic-go/masque-go` — CONNECT-UDP client + proxy, MIT.

Active CVE list for quic-go as of 2026: CVE-2024-22189, CVE-2024-45396, CVE-2024-53259, CVE-2025-29785, CVE-2025-59530. Most are DoS / panic-class. We track these via §19 (vulnerability handling).

### 5.4 TLS

- TLS 1.3, ALPN `h3`.
- Server cert: self-signed **ECDSA P-256** (not Ed25519) by default. Rationale: Ed25519 is rare enough on real web servers in 2026 that a self-signed Ed25519 cert is a fingerprint by itself. Public CAs (Let's Encrypt etc.) do not issue Ed25519 certs as of early 2026. ECDSA P-256 covers both self-signed and public-CA modes.
- Cert generated by the relay at first start, persisted at `/var/lib/wireguardrtc-relay/tls.{key,crt}`, mode `0600 wireguardrtc-relay:wireguardrtc-relay`. The daemon does **not** read or write this file directly. The relay publishes its cert fingerprint to the daemon via the control socket; the daemon includes it in `SasEnrollInfo.endpoints[*].fingerprint`.
- For admin-managed deployments with a public domain, the admin can replace the cert with a CA-signed one (same path; relay reloads on SIGHUP).
- SNI: whatever the host configured. Defaults to a randomly-chosen plausible value (e.g., a CDN provider's apex hostname like `cdn.example.org`) at first daemon start. Admin can override via config. The listener accepts any SNI; only the URI path and the URL token are load-bearing for routing.

### 5.5 QUIC keep-alive and idle timeout

QUIC PING frame on a 15s keep-alive timer. Idle timeout 60s. Connection-ID rotation enabled (default in quic-go); this is a privacy feature (defends against path-migration *linkability* across mobile network rebinding) — not an anti-DPI feature, and we make no claim that it hides the 5-tuple from passive observers.

### 5.6 Datagram extension required

RFC 9221 QUIC datagrams must be supported. Both `quic-go` and `masque-go` support this. We require it; a peer that doesn't support datagrams is rejected.

quic-go does **not** expose a `MaxDatagramFrameSize` configuration knob in `quic.Config` (the only datagram-related public field is `EnableDatagrams bool`). The library computes the effective frame size internally from the peer-advertised transport parameter, capped by an internal constant (16383 bytes in current master). For our 1200-byte inner WG MTU (§13.2), the default internal cap is more than sufficient; no override needed. If a future quic-go release reduces the internal cap below ~1500 bytes, we vendor and patch — but for v0.3 we rely on quic-go's default and pin the dependency version to one we've verified.

### 5.7 Capsule fallback explicitly rejected

If datagram negotiation fails (e.g., a peer advertises `MaxDatagramFrameSize = 0`), the implementation falls back to capsule-protocol-over-streams per RFC 9298 §6. This is **reliable + ordered**, which kills the latency benefit and makes WG-over-MASQUE behave like WG-over-TCP. We do not enable this fallback. If both sides cannot use datagrams, MASQUE fails the connection attempt and the joiner falls back to WSS (which is unconditionally reliable-ordered, but with the right semantics for that mode).


## 6. Transport: WebSocket-over-TLS

### 6.1 Wire format

Standard RFC 6455 WebSocket over TLS 1.3 (`wss://`). Each WG UDP datagram is one binary WS frame, payload = raw WG bytes. WS frame header is 2-6 bytes server-to-client (no masking required for server frames per RFC 6455 §5.1) and 6-10 bytes client-to-server (4-byte mask key).

### 6.2 No multiplexing inside WSS

We considered batching multiple WG datagrams per WS frame. Decision: don't. Per-frame keeps semantics aligned with MASQUE (one frame = one WG datagram) and avoids HoL blocking concerns. Future optimization if measured to matter.

### 6.3 Keep-alive layers

Three keep-alive timers operate in WSS mode, and the doc names all three explicitly:
- **Inner WG** keep-alive: 25s (per PS26 memory and `WgQuickUapi` default).
- **WSS layer** ping: 30s, via RFC 6455 PING frames. CDN proxies treat these as activity for their idle-timeout purposes.
- **TCP layer**: SO_KEEPALIVE off (TCP retransmit handles dead-peer detection in <60s). No application change needed.

Note that any reverse-proxy front (Cloudflare, Caddy, nginx) typically has its own idle timeout (Cloudflare's is 100s on the free plan). Our 30s WSS ping is well under it.

### 6.4 Library

- `github.com/coder/websocket`, ISC license. Modern context-aware API. Active fork of the unmaintained `nhooyr.io/websocket`. Pin a tagged version.

Vendored alongside quic-go via `go mod vendor`.

### 6.5 URL form

```
wss://<host>:<port>/wgrtc/v1/ws/<peer-token>
```

Same per-peer token as MASQUE.

### 6.6 Reverse-proxy fronting (CDN/self-hosted)

WSS is designed to work behind a reverse proxy. Both **self-hosted** (Caddy, nginx, HAProxy) and **commercial CDN** fronts are valid deployment patterns. The relay listens on a private port (e.g., localhost:8443); the front terminates TLS and proxies WS upgrades end-to-end to the relay.

**On Cloudflare specifically**: Cloudflare's Self-Serve Subscription Agreement (updated 2024-12-03) prohibits running proxy/VPN services on Cloudflare's network without explicit approval. Free-tier deployments of wgrtc-via-Cloudflare-WSS are **out of policy** even though they are *technically* feasible (the V2Ray-over-Cloudflare community has demonstrated this configuration for years). We do not officially endorse Cloudflare-free-tier as a wgrtc deployment target. The deployment guide will recommend self-hosted reverse proxies as the canonical CDN-fronting path. Admins who choose a commercial CDN are responsible for verifying compatibility with that CDN's ToS.

### 6.7 Backend protocol from front to relay

When deployed behind a reverse proxy, the proxy-to-relay leg is plain WS over TCP on the loopback or LAN. The TLS termination happens at the front; the relay does not terminate TLS in this configuration. Config flag: `--tls-passthrough` (matches the existing daemon's Go-flag style).


## 7. Authentication and trust

### 7.1 Two-tier secret separation

Token derivation uses a **separate, persisted, rotatable secret** distinct from the WG private key. This means:
- The URL token survives WG key rotation (no need to re-pair all peers if the host's WG private key changes).
- The URL token rotates independently if the admin chooses (`wireguardrtc --rotate-url-tokens`), forcing re-pairing for everyone.
- A leak of the WG private key does not leak URL tokens (and vice versa).

The persisted secret is 32 bytes of random data at `/etc/wireguardrtc/url-token-root.key`, mode `0600 root:wireguardrtc`, generated by the daemon at first start.

### 7.2 Per-peer URL token

```
token_bytes = HMAC-SHA256(
  key = url_token_root_key,
  msg = "wgrtc/obf/url-token/v1" || peer_wg_pubkey || enrollment_nonce
)[:16]

token_url_segment = base64url(token_bytes)  // 22 chars
```

Where:
- `enrollment_nonce` is 16 random bytes generated at enrollment, persisted in the peer's drop-in config under `EnrollmentNonce = base64(...)`. Re-enrolling a peer (or running `--rotate-peer-nonce`) generates a fresh nonce, rotating the token.
- The protocol label `"wgrtc/obf/url-token/v1"` is a wire-format constant, listed alongside `PROTOCOL_LABEL` in CLAUDE.md §6 once this lands.

Properties:
- Unique per peer.
- Stable for the lifetime of one enrollment.
- Rotatable on demand (re-enroll, rotate nonce, or rotate root key).
- Indistinguishable from random to a probe-only observer.
- Lost-credential recovery: rotate the root key, force-re-pair every peer.

### 7.3 Token lookup is constant-time

The relay's listener maintains a map keyed by **the SHA-256 hash of the token bytes**, not the raw token. The path's token is hashed before lookup; the result is keyed against the map; a final `subtle.ConstantTimeCompare` of the bytes confirms the match (defense in depth — hashing already removes the timing-attack surface on map operations). Unknown tokens get an indistinguishable response from invalid paths: 404 generic decoy (§13).

### 7.4 TLS server identity

Either:
- **Pinned self-signed (default)**: SHA-256 fingerprint of the leaf cert shipped in `SasEnrollInfo.endpoints[*].fingerprint`. Joiner pins via `tls.Config.VerifyPeerCertificate`.
- **Public CA (admin opt-in)**: host advertises `"ca": "public", "sni": "<hostname>"`; joiner uses system root store + hostname validation. Recommended for static-IP/public-domain deployments.

Cert keypair: **ECDSA P-256** for both modes (matches what public CAs issue; cuts the "self-signed Ed25519 cert is itself a fingerprint" risk).

### 7.5 Cert rotation

The relay rotates its cert on `wireguardrtc-relay --rotate-cert` (manual) or when the file is replaced and SIGHUP is sent. To handle the joiner-still-has-old-fingerprint case, the daemon maintains an **acceptance window**: it advertises the new fingerprint via `SasEnrollInfo` on next pairing, but it continues to honor the old fingerprint for `cert_grace_period` (default 30 days). The relay serves either cert based on SNI or randomly (sticky per-connection). After the grace period, the old cert is removed.

Joiners that haven't re-paired within the grace window get a TLS failure and fall back to a non-MASQUE transport, prompting the user to re-pair.

### 7.6 Application-layer mutual authentication

The URL token authenticates the *request*. The actual peer identity is established by the WG handshake inside the tunnel — same as direct-WG mode. So the obfuscation layer is a coarse "is this client one of our enrolled peers" gate; the WG layer is the cryptographic peer identity. Defense in depth.

### 7.7 Why not mTLS

Considered. Rejected because: (a) client cert auth is rare in real HTTPS traffic and is itself a fingerprint, (b) the URL-token + WG-handshake pair has equivalent security properties, (c) avoids a separate per-peer identity material beyond what we already have.

### 7.8 Protocol label registry

To prevent collisions, all new HMAC/key-derivation labels live in a single source-of-truth file. Initial entries:
- `"wgrtc/obf/url-token/v1"` — §7.2 URL token
- `"wgrtc/obf/cert-binding/v1"` — TLS fingerprint binding (if needed for advanced cert verification)

Existing labels (signaling box, etc.) get listed too. New labels go through a one-paragraph review before being added.


## 8. Decoy site and probing resistance

### 8.1 Default decoy content (uniform across deployments)

All wgrtc relays serve the **identical** default decoy site for unauthenticated requests. Hashing per-host for variety would make every wgrtc deployment uniquely-fingerprintable; uniformity means a censor can identify "this is a wgrtc decoy" but cannot enumerate or distinguish individual deployments by content.

The decoy site is a simple, anodyne "Site under maintenance" static HTML page. ~2 kB total. Identical on all wgrtc deployments. Admins can replace it with their own decoy via `--decoy-dir /path/to/decoy/` (then it's *their* fingerprint, not wgrtc's).

```
GET /             → 200 "Site under maintenance" (canonical static HTML)
GET /favicon.ico  → 200 generic 16x16 PNG, ETag-stable
GET /robots.txt   → 200 "User-agent: *\nDisallow: /\n"
GET /<unknown>    → 404 byte-for-byte stable response body (no server identification)
```

The 404 response is exactly: `HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: 152\r\n\r\n<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>` — matching the bare-minimum form many web servers serve.

### 8.2 Auth-failure responses

```
WS upgrade with wrong path           → 404 (identical to §8.1)
WS upgrade with unknown token        → 404 (identical to §8.1)
CONNECT-UDP with wrong path          → 404 (identical to §8.1)
CONNECT-UDP with unknown token       → 404 (identical to §8.1)
```

Same response for all four failure modes. No timing or content side-channel.

### 8.3 Rate limiting (three-tier)

- **Burst tier**: per source IP, 60 requests in 60 seconds (token bucket, burst capacity 60). Exceeded → 429 with `Retry-After: 60`.
- **Sustained tier**: per source IP, 600 requests/hour. Soft cap for botnets that pace themselves around the burst tier.
- **Daily tier**: per /24 source subnet, 50,000 requests/day. Catches large coordinated probe campaigns.
- Failed-auth and successful-auth use separate buckets; a probe campaign cannot 429 legitimate users.

### 8.4 Logging discipline

- Failed-auth: logged at INFO with source IP, path (truncated to first 40 chars), timestamp. **NEVER** the full URL token.
- Per-IP log throttling: after 100 failed requests from the same source IP/min, log "rate-limit-suppressing further logs from <ip>" once, then drop. Resumes after 5 min cool-down.
- Burst log cap: 1 MB/minute. Beyond that, only counters increment.
- Daily log cap: 10 MB/day for failed-auth combined. Beyond that, only counters.
- Successful: pubkey + transport, nothing else.

### 8.5 Acknowledged limitations

We do **not** (yet):
- Mimic specific real CMSs (WordPress, Drupal, Joomla headers, cookies).
- Serve TLS handshakes shaped like Chrome/Firefox (uTLS-for-QUIC is future work).
- Defeat ECN/timing-based traffic analysis.

These are arms-race work for v0.4+.


## 9. Auto-discovery and fallback

### 9.1 Connection attempt sequence

```
network_id = currentNetworkIdentity()  // §9.4
cached = cache.get(tunnel_id, network_id, endpoints_hash)

if cached != null and not cache.stale(cached):
  result = tryTransport(cached.transport, timeout=3s)
  if result == ok:
    return result
  invalidateCache(cached)  // FAIL-FAST: don't wait for TTL on a stale cache hit

# Full happy-eyeballs probe
results = ParallelProbe with the following timing:
  t=0:    start direct-WG candidate race (existing logic, v4 + v6)
  t=100ms: if no WG handshake completed yet, also start masque dial(s)
  t=300ms: if still no success, also start wss dial(s)
  t=10s:  total timeout; fail with structured error

winner = first transport to complete ALL of:
  - TCP/QUIC outer handshake AND
  - URL token accepted (no 404) AND
  - first WG handshake response OR a relay-side application-layer keepalive received through the transport within 5s of token acceptance

cache.set(tunnel_id, network_id, endpoints_hash, winner.transport, ttl=24h)
return winner
```

The "WG handshake response OR keepalive" criterion guards against the failure mode where the outer transport completes but the host-side daemon is asleep (wake-via-iface for v4 takes up to ~1s; the relay must therefore emit a small application-layer keepalive immediately on token acceptance so the joiner can confirm end-to-end liveness without waiting for kernel WG).

### 9.2 Fail-fast cache invalidation

If the cached transport's `tryTransport` call fails or times out, **the cache entry is immediately invalidated**, not allowed to live to its TTL. This handles the "corporate IT blocks QUIC at noon" case: the morning's MASQUE-worked cache hit fails, gets evicted, full probe runs, finds WSS, caches that. Joiner experiences ~6s extra delay once, then converges.

### 9.3 24h TTL

24 hours as the upper bound on a positive cache. Mainly defends against the case where a network's policy improves (e.g., MASQUE becomes available where previously it was blocked) — the cache eventually expires and re-probes.

### 9.4 Network identity per platform

The cache key includes `network_id`. Computed differently per platform. All hash operations use BLAKE2b with a 16-byte local-only secret (never logged, never transmitted) so that gateway MAC addresses do not appear in plaintext in log lines or error reports.

**Android:**
- Wi-Fi: `wifi:<blake2b(SSID, local_secret)>` *if* SSID is readable (requires `ACCESS_FINE_LOCATION` per API 26+ rules). Without that permission, every Wi-Fi network looks identical to the cache. The gateway-MAC fallback is unavailable on Android 11+ (uid-isolated `/proc/net/arp`). The wgrtc onboarding flow requests location permission with the rationale "to remember which Wi-Fi networks need TCP fallback for VPN."
- Cellular: `cellular:<carrier_id>` (read from `TelephonyManager.getNetworkOperator()`).
- Ethernet/USB-tether: `ethernet:<blake2b(local_ipv4_prefix, local_secret)>` (a coarser identity, but workable).
- VPN-on-VPN nested (e.g., joiner inside an enterprise VPN): `vpn:<uplink_interface_name>`.
- No-permission fallback: `unknown:<random_session_id>` — cache mis-hits each session (we re-probe every time), slower but correct.

**Linux daemon:**
- Default gateway MAC address `blake2b`-hashed (via `ip neigh` for unprivileged users; falls back to local IPv4 /24 prefix if MAC unavailable) + uplink interface name. `gw:<blake2b(mac, local_secret)>/<iface>`.

Documented mis-hit cases:
- Android without location permission: all Wi-Fi networks share a cache slot. We accept this. Functionally: each new Wi-Fi session re-probes; ~6s extra connect latency once per session, no correctness issue.
- Cellular roams between carriers re-key correctly.
- A NAT gateway swap (rare) re-keys (correctly forcing a re-probe).

### 9.5 Cache key includes endpoints hash

Cache key: `(tunnel_id, network_id, endpoints_hash)` where `endpoints_hash = SHA-256(sorted(endpoints))[:8]`. If the host updates its endpoint list (new MASQUE endpoint added, etc.), the cache key changes and the joiner re-probes.

### 9.6 Why not eager parallelism (race all three from t=0)

The 100/300 ms gates keep the common case (direct WG works) fast and cheap. Starting MASQUE and WSS at t=0 wastes a 1200-byte QUIC Initial + a TCP SYN every time direct WG was going to win in 50 ms. The cost on the slow case (direct WG fails silently) is the 100 ms delay before MASQUE, which is negligible relative to the seconds-long timeout direct WG eventually hits.

If field data shows direct WG silently fails on >25% of connection attempts (rare but possible in some censored deployments), tighten the gates further or move to t=0 parallelism.

### 9.7 Why not config-driven preference

Users don't know what works on their current network. Admins know what the host supports but not what the joiner sees. Cache-based discovery converges to the right answer in <1 connection per (tunnel, network).


## 10. Hole punching

### 10.1 The good news (direct-WG and MASQUE share NAT mechanics)

QUIC over UDP/v4 punches with the same mechanics as WG/UDP. Our existing `inject_raw_udp()` trick (CLAUDE.md §7) opens a NAT pinhole; QUIC Initial packets from both sides immediately follow and complete the handshake through the pinhole.

### 10.2 Punch packet format for MASQUE

Per §10.6, v0.3 MASQUE does not require the daemon to punch on the joiner's behalf — the relay simply listens on a reachable port. This section is informational, deferred for v0.4+ MASQUE-p2p (§10.7).

If/when we revisit, the design hypothesis is: a 1-byte UDP payload of `0x00`. Reasoning:
- Empty UDP fails ICMP-port-unreachable on some middleboxes.
- A 1-byte payload is plausible "stray UDP."
- quic-go's `Transport.run()` will discard it as an unparseable QUIC header (1 byte cannot be a valid QUIC Long Header).
- No Version Negotiation response triggered (those require 5+ bytes with QUIC long-header bit set).

Validation deferred to whatever phase first implements MASQUE-p2p: test traversal on a representative sample of real CGNAT / SOHO routers before locking in.

### 10.3 NAT timeout

Linux conntrack defaults: `nf_conntrack_udp_timeout=30s` for unestablished flows, `nf_conntrack_udp_timeout_stream=120s` once bidirectional traffic has been seen. QUIC's 1-RTT handshake quickly promotes the flow to "stream" status, after which our 15s keep-alive reliably refreshes the 120s timer. Home/SOHO routers with shorter UDP timeouts (5–10s) require the *initial* user traffic to fire within their window, otherwise the pinhole closes and another punch is needed. Direct-WG mode already navigates this — MASQUE inherits the same behavior.

### 10.4 IPv6

No hole punching on v6 (consistent with §2.2 of the IPv6 design doc). v6 MASQUE/WSS connects directly to advertised endpoints.

### 10.5 WSS hole punching is impossible

TCP requires a listener; you cannot punch a NAT pinhole into a TCP listening socket. WSS therefore works only when **at least one side has a reachable endpoint** — static IP, port-forwarded home server, or reverse-proxy-fronted CGNAT host. For two CGNAT-behind peers with no reachable endpoint and no reverse proxy, WSS is unavailable; the joiner's auto-discovery silently drops WSS from its candidate set.

This is the most important asymmetry between MASQUE and WSS, and the auto-discovery layer (§9) accounts for it: a joiner with no reachable peer endpoint will not attempt WSS.

### 10.6 v0.3 MASQUE requires a reachable host endpoint (no daemon-side punch RPC)

**Committed scope decision**: in v0.3, MASQUE requires the host (relay-side) to have a publicly-reachable UDP port. The joiner dials in; the relay does not punch on the joiner's behalf. The CGNAT-host-with-CGNAT-joiner case falls back to direct WG (which we punch successfully) or WSS through a reverse-proxy front (§6.6).

This matches WSS's same asymmetry (§10.5) and removes a cross-process punch RPC from the v0.3 control plane. The relay's listen port is bound at startup; the daemon's existing raw-UDP injection (CLAUDE.md §7) handles the host-side hole-punching for direct-WG mode only.

### 10.7 MASQUE peer-to-peer (deferred to v0.4+, EXPERIMENTAL)

For two-CGNAT-peer MASQUE, both relays would need to run a QUIC `Transport` listener+dialer on the same UDP socket, both punch via raw-UDP injection, both race "client" and "server" QUIC handshakes.

**This is research-grade work**. Simultaneous-QUIC-from-both-sides between NAT'd peers is not addressed in RFC 9000 the way TCP simultaneous-open is in RFC 793 §3.4. libp2p's hole-punching effort (Marten Seemann et al., 2021–present) reports mixed real-world results.

We defer this to v0.4+ as an experimental opt-in (`Transports = masque-p2p`), not v0.3. The deferral lets us track libp2p's work and pick up working primitives if/when they stabilize, without blocking v0.3 shipping. Implementation in v0.4 would add a `punch_endpoint` control-plane RPC for daemon-to-relay coordination.


## 11. Daemon-side architecture

### 11.1 Component layout

```
                       /etc/wireguardrtc/
                          peers.d/<label>.conf
                          url-token-root.key       (root:wgrtc-shared-secrets 0640)

                       /var/lib/wireguardrtc-relay/
                          tls.key, tls.crt         (wireguardrtc-relay:wireguardrtc-relay 0600)
                          relay-state.json         (allocations, version vector)

                       /run/wireguardrtc/
                          lock                     (existing)
                       /run/wireguardrtc-relay/
                          control.sock             (daemon ↔ relay control)

   ┌──────────────────────┐         ┌──────────────────────┐
   │ wireguardrtc         │ ◄─────► │ wireguardrtc-relay   │
   │  (Python, existing)  │ control │  (Go, new)           │
   │                      │  plane  │                      │
   │  - signaling         │         │  - MASQUE listener   │
   │  - peers.d watcher   │         │    + dialer (§11.6)  │
   │  - calls wg set/show │         │  - WSS listener      │
   │  - URL-token gen     │         │    + dialer          │
   │  - hole-punching     │         │  - cert lifecycle    │
   │  - generates SAS     │         │  - decoy site        │
   │  - publishes cert FP │         │                      │
   └──────────────────────┘         └──────────────────────┘
                                              │
                                              │ per-peer
                                              ▼  UDP socket
                                       127.0.0.1:51820 (kernel WG)
```

### 11.2 Per-peer localhost socket

For each peer whose `Transports` set includes `masque` or `wss`, the relay holds one UDP socket bound to `127.0.0.1:<allocated>`. Allocated port is stable for the peer's lifetime, drawn from `[49152, 65535]` to avoid clashing with system services. The allocation is persisted in `/var/lib/wireguardrtc-relay/relay-state.json` and protected by `flock` (same pattern as the daemon's lock).

The Python daemon configures kernel WG with `endpoint = 127.0.0.1:<allocated>` for these peers. From kernel WG's perspective, these are local LAN peers — no NAT, no roaming.

### 11.3 Control plane reconciliation

Unix socket `/run/wireguardrtc-relay/control.sock`. JSON-line protocol, **reconciliation-based** (not transactional) plus a small event-push channel for low-latency updates:

```
{"op": "hello", "version": 1}                            // sent on connect, both sides
{"op": "list_peers"}                                     // → {"peers": [...]}
{"op": "set_peers", "peers": [...]}                      // full reconciliation (atomic on relay side)
{"op": "peer_stats", "pubkey": "..."}                    // → {"rx_bytes": ..., ...}
{"op": "cert_fingerprint", "fingerprint": "sha256:..."}  // pushed by relay on cert change
{"op": "rotate_cert"}                                    // → relay rotates cert, replies "ok"
```

The daemon polls `set_peers` every 30s with the full desired state. The relay diffs against its current state and reconciles. Each entry in the `peers` list carries a stable hash so the relay can skip unchanged entries on diff — meaningful at 2k-peer scale.

For sub-30s peer-add propagation (admin adds a peer, the new peer connects immediately), the daemon sends `SIGUSR1` to the relay after writing to `peers.d/`. The relay's signal handler triggers an immediate `set_peers` round-trip, dropping the worst-case admin-add → joiner-connect latency from 30s to <1s.

After a relay crash + restart, the daemon's next poll cycle re-syncs everything. No transactional ordering, no version vector — full state every time, idempotent.

### 11.4 Capability split

systemd-managed two-process model. Both processes are supplementary members of a shared `wgrtc-shared-secrets` group used solely for cross-process secret reads.

| Process | User | Groups | Caps | Reads | Writes |
|---|---|---|---|---|---|
| `wireguardrtc.service` | `wireguardrtc` | `wireguardrtc`, `wgrtc-shared-secrets` | `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_NET_BIND_SERVICE` | `/etc/wireguardrtc/`, `/var/lib/wireguardrtc/` | `/etc/wireguardrtc/url-token-root.key` (initial gen + admin-triggered rotation only) |
| `wireguardrtc-relay.service` | `wireguardrtc-relay` | `wireguardrtc-relay`, `wgrtc-shared-secrets` | `CAP_NET_BIND_SERVICE` (for ports <1024) | `/etc/wireguardrtc/url-token-root.key` (read-only via `wgrtc-shared-secrets` group access) | `/var/lib/wireguardrtc-relay/`, `/run/wireguardrtc-relay/` |

Both processes have `NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=true` (matching the existing daemon's hardening).

The URL-token-root key is owned `root:wgrtc-shared-secrets`, mode `0640`. The postinst script creates `wgrtc-shared-secrets` if absent and adds both service users to it. Removing either package drops the user from the group; removing both packages removes the group.

The TLS cert is **owned by the relay**, not the daemon. The relay generates, rotates, and publishes the fingerprint to the daemon via control socket. The daemon does not need access to `tls.{key,crt}`.

### 11.5 Hole-punching scope

In v0.3, the daemon performs raw-UDP injection only for `direct` peers (CLAUDE.md §7 unchanged). MASQUE peers do **not** trigger daemon-side hole-punching — per §10.6, MASQUE in v0.3 requires the relay-side to have a reachable UDP listen port. The relay listens on its bound port; joiners dial in.

If a deployment is behind CGNAT and cannot expose a public UDP port for MASQUE, the joiner falls back to direct-WG (where punching works for v4) or to WSS through a reverse-proxy front. This eliminates the need for a daemon↔relay punch-coordination RPC in v0.3.

(v0.4+ MASQUE-p2p in §10.7 would add a `punch_endpoint` control-plane op. Out of v0.3 scope.)

### 11.6 Daemon as MASQUE/WSS client (outbound)

For cascading tunnels and interop tests, the relay implements both client and server. Peer drop-in config with `Transports = client-masque` or `client-wss` directs the relay to dial outbound to a remote MASQUE/WSS listener rather than accept inbound. Other than direction-of-dial, the data path (localhost UDP socket ↔ obfuscated transport) is identical.

Realistic implementation estimate: **1500–2500 lines** including tests, covering: HTTP/3 client construction (joiner-side sentinel-URL workaround per §5.2), cert pinning vs. system-CA validation, ALPN negotiation, URL token derivation, retry+backoff, network-id-aware reconnection, integration with the auto-discovery scheduler (§9), unit + integration tests for both transports. Phase 5 timing accounts for this.

### 11.7 Resource limits

- `LimitNOFILE=65536`. Each peer needs ~2 FDs (localhost UDP socket + obfuscated transport connection); 2k peers = ~4k FDs. The headroom covers concurrent probe connections, control socket, journald output.
- Max peers per relay: **2048** (configurable in `/etc/wireguardrtc/relay.conf`). The binding constraint at this scale is **per-peer goroutine memory** (~8 KiB stack × ~3 goroutines per peer = ~50 MiB at 2k peers; well under `MemoryMax=1G` from §16.4). Beyond 2k peers, control-socket message size for `set_peers` grows past the unix-socket-recvbuf default; if a deployment needs more peers, increase `net.core.rmem_max` and reconfigure. 2048 is a sane default; deployments scale linearly until JSON-parsing CPU on the 30s poll becomes the bottleneck (estimated ~10k peers on typical hardware).
- Max concurrent unauthenticated probe connections: 256 (rate-limited per §8.3).


## 12. Android-side architecture

### 12.1 Component layout

The existing wgbridge_native already runs wireguard-go in userspace. We extend it with:

- `transport/masque.go` — MASQUE CONNECT-UDP client + listener.
- `transport/wss.go` — WSS client + listener.
- `transport/auto.go` — happy-eyeballs scheduler from §9.

Each transport exposes the same `PacketTransport` interface to wireguard-go's `tun.Device` abstraction. We swap out wireguard-go's default UDP socket binding for our transport object when `Transport != direct`.

### 12.2 APK size impact

Adding `quic-go` + `masque-go` + `coder/websocket` to wgbridge_native's cgo build pulls in roughly 40-60k lines of Go. Current `libgojni.so` is ~7 MB stripped per ABI; expected post-obfuscation size 10-13 MB per ABI. With two supported ABIs (arm64, x86_64) the APK grows by ~10-15 MB total. We accept this. The AAB Play-Store splits make this less painful per-install.

### 12.3 No changes to JoinerNController (per-tunnel transport choice)

The joiner-N machinery (one VpnService TUN, N wireguard-go bridges via gvisor) is orthogonal to transport choice. Each bridge picks its own transport based on tunnel config; they coexist trivially.

**Network selection per tunnel** (PS13-style) extends to per-transport: a tunnel can be MASQUE-over-cellular while another is direct-WG-over-wifi. The auto-discovery layer's `network_id` (§9.4) feeds into this, and per-tunnel network preference is unchanged from v0.2.x.

### 12.4 The protect() boundary

VpnService.protect() must wrap **every** socket the obfuscation transport opens. Both `quic.Transport` and the WS library expose a `Dialer` with a `Control` callback where we apply protect(). Same pattern as the existing direct-WG socket.

For **listener mode on Android** (§12.5):
- **UDP listening sockets (MASQUE/QUIC)** are protected once at bind time.
- **TCP listening sockets (WSS)** are protected once at bind time, *and each accepted socket out of `ServerSocket.accept()` is a fresh fd that must be `protect(accepted)`-ed immediately, before any read or write*. Without this, the accepted connection's bytes route into the VpnService TUN and create a loop. Listener implementation wraps `accept()` in a helper that calls `protect()` first and only then hands the socket to the application layer. Tested at Phase 5 with a deliberate provocation (host-mode tunnel up, MASQUE listener bound, joiner dials in over WSS — verify accepted socket isn't routed through VPN).

### 12.5 Android as MASQUE/WSS server (host-mode obfuscation)

For phones acting as hosts on hostile networks. Architecture:

- HostModeBackend's existing foreground service already binds a public UDP port for direct-WG host-mode. We extend it to also bind:
  - One UDP socket for QUIC/MASQUE listening (separate from direct-WG socket).
  - One TCP socket for WSS listening.
- TLS cert generated at first host-mode launch, persisted in app-private storage, fingerprint pinned via the SAS payload.
- Decoy site served from the same HTTP handler. Static templates baked into the APK.
- The relay-to-WG step is shorter on Android: no kernel WG; we deliver decapsulated UDP packets directly to wireguard-go's existing `tun.Device` interface via the transport plugin.

**Foreground service type**: committed to **`specialUse`** with declared `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` justification. Reasoning:
- `dataSync` was the type Orbot was killed on in 2024 (Google ruled VPN-adjacent network proxying is out of scope for that type — see [Orbot issue #1263](https://github.com/guardianproject/orbot-android/issues/1263)). Avoid.
- `connectedDevice` (current host-mode default) is for Bluetooth/USB companion devices, semantically wrong for "phone-as-public-network-server."
- `systemExempted` is reserved for system-Settings-configured VPN apps and doesn't apply to a standalone-listener foreground service.
- `specialUse` with explicit justification ("Host-mode WireGuard tunnel listener with HTTPS-mimicry transport; user-initiated, foreground-required for inbound connection availability") fits the actual semantic.

Justification text (baked into AndroidManifest.xml `<property>` element):
```xml
<property
    android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE"
    android:value="WireGuard host-mode tunnel listener with optional MASQUE/WSS transport obfuscation. User-initiated and user-visible; required for inbound connections to remain available while the app is in background." />
```

This applies to both direct-WG host-mode (which currently uses `connectedDevice`) and the new MASQUE/WSS listener modes — they share the same foreground service. Phase 5 includes the manifest migration; Phase 8 includes a Play Store re-submission walkthrough.

### 12.6 Android as MASQUE/WSS client (joiner-mode obfuscation)

The typical case. Joiner discovers the host's MASQUE/WSS endpoints from the SAS payload, dials through the obfuscated transport, tunnel works end-to-end.


## 13. MTU

### 13.1 Per-packet overhead

Values below are approximate (±5 bytes) — exact size depends on QUIC packet-number encoding, varint widths, and whether the connection has rotated to short-header mode. For sizing the inner WG MTU we apply conservative rounding (§13.2).

| Layer | v4 outer | v6 outer |
|---|---|---|
| Outer IP | 20 | 40 |
| Outer UDP/TCP | 8 / 20 | 8 / 20 |
| QUIC short header (DCID 8B + pkt num 1-4B + flags 1B) | ~12 | ~12 |
| QUIC AEAD tag | 16 | 16 |
| QUIC DATAGRAM frame type (0x30, varint) | 1 | 1 |
| HTTP Datagram Quarter Stream ID (varint, typ. 1B) | 1 | 1 |
| HTTP Datagram Context ID (varint, always 0 for CONNECT-UDP) | 1 | 1 |
| **Total MASQUE outer (approx.)** | ~59 | ~79 |
| TLS 1.3 record header | 5 | 5 |
| TLS 1.3 AEAD tag | 16 | 16 |
| WS frame header server→client, payload 126–65535 (no mask) | 4 | 4 |
| WS frame header client→server, payload 126–65535 (with mask) | 8 | 8 |
| **Total WSS client→server outer (approx.)** | ~69 | ~89 |
| **Total WSS server→client outer (approx.)** | ~65 | ~85 |

WG itself adds 32 bytes inside the obfuscation tunnel (existing).

For a 1500B outer link:
- MASQUE v4 inner WG max: 1500 - 62 = **1438** (with 32B WG overhead, useful payload = 1406)
- MASQUE v6 inner WG max: 1500 - 82 = **1418** (useful = 1386)
- WSS v4 inner WG max: 1500 - 71 = **1429** (useful = 1397)
- WSS v6 inner WG max: 1500 - 91 = **1409** (useful = 1377)

### 13.2 Conservative defaults

We set the **inner WG MTU = 1200 bytes** for all obfuscation-mode tunnels. Reasoning:
- Leaves headroom for QUIC DPLPMTUD convergence (which can take seconds — the first user packet should not be dropped).
- Survives reverse-proxy chains that add their own headers (Cloudflare's `cf-*` headers, X-Forwarded-For, etc.) without fragmentation surprises.
- IPv6 minimum MTU is 1280; a 1200-byte inner well-clears with all overhead even on IPv6.
- 1200 is sufficient for most user traffic; PMTUD inside the WG tunnel does the right thing for outbound TCP.

### 13.3 quic-go datagram frame size

We rely on quic-go's internal default (16383 bytes in current master), which is well above our 1200B inner WG payload. The library negotiates the effective frame size per-connection from the peer's advertised transport parameter; both endpoints announce support via `quic.Config{EnableDatagrams: true}`. No application-level override needed.

If a future quic-go release reduces the internal cap below ~1500 bytes, Phase 4 acceptance tests catch it (we ship synthetic-1200B-payload roundtrip tests in CI against the pinned quic-go version). At that point we either pin to a working version or vendor a patch.

### 13.4 MtuMath extension

Add `OuterFamily.MASQUE_V4 / MASQUE_V6 / WSS_V4 / WSS_V6` cases. Tests pin the overhead values from §13.1.

### 13.5 PMTUD events

quic-go's PLPMTUD runs in the background. We let it converge.

The "inner WG never generates packets >1200" property relies on the joiner's WG interface having `MTU=1200` configured. We enforce this:
- **Android joiner**: `JoinerVpnService.Builder.setMtu(1200)` for tunnels whose host advertises any obfuscation transport (existing direct-only tunnels keep their current MTU).
- **Linux wg-quick joiner**: auto-generated configs include `MTU = 1200` under `[Interface]` for obfuscation-mode tunnels. Existing direct-mode wg-quick configs are unchanged.
- **MSS clamping**: WG-protocol tunnels rely on MSS clamping (`iptables -t mangle -A FORWARD ... --clamp-mss-to-pmtu` or equivalent) to keep TCP inside the MTU. For obfuscation-mode tunnels the daemon's `wg set` includes the MTU; the joiner's `wg-quick` integration includes a `PostUp` line to enable MSS clamping for the WG interface on Linux joiners.


## 14. Signaling protocol extensions

### 14.1 SasEnrollInfo additions

```kotlin
// Existing
val assignedAddress: String
val allowedIps: String
val wgEndpoint: String?

// New, optional, all default to null/empty for backwards compat
val endpoints: List<Endpoint>?
val endpointsVersion: Int?       // 1 = v0.3 schema; null = older
val urlToken: String?            // per-peer; 22-char base64url; the canonical value
```

`urlToken` is the **canonical token value** for this peer. The joiner constructs MASQUE and WSS URLs from `urlToken` plus per-endpoint host/port/path information:
- MASQUE URL: `https://<endpoint.host>:<endpoint.port>/<urlToken>/wgrtc/v1/cu/...`
- WSS URL: `wss://<endpoint.host>:<endpoint.port>/wgrtc/v1/ws/<urlToken>`

This lets a joiner construct alternate URLs (different SNI front, different reverse-proxy front) from the same token without needing the host to re-issue. The `endpoint.url` field in §4.2 is purely a convenience pre-formatted URL for the canonical case.

**Backwards compatibility**: a v0.2.x joiner reads only `wgEndpoint` and ignores `endpoints`. A v0.3+ joiner prefers `endpoints` if present, falls back to `wgEndpoint` otherwise. A v0.2.x host's payload (no `endpoints`) is read by a v0.3+ joiner as direct-mode only.

**kotlinx.serialization risk** (per `feedback_kotlinx_serialization_defaults` memory): the existing `Json` instance must continue to serialize with `encodeDefaults=true` after this addition. The new fields are wrapped in `Optional<>` / nullable types specifically so this property is preserved. Tests pin this invariant.

### 14.2 Peer drop-in config (daemon)

The existing `Mode = active|passive|dns-roam|ignore` key controls **daemon signaling behavior** for the peer and is **not** overloaded. We add a separate orthogonal key for transports:

```ini
[Peer]
PublicKey = ...
Mode = active                              # existing: signaling behavior
Transports = direct, masque, wss           # NEW: which transports the daemon accepts
EnrollmentNonce = base64...                # §7.2
EndpointHint = 203.0.113.5:443             # optional override for masque/wss listen
```

`Mode = ignore` peers are not given a `Transports` line (or it's ignored).

`Transports` is comma-separated. Order is **not significant**; it's a set, not a preference list (preferences are decided per-connection by §9).

`Transports` defaults to `direct` if missing — full backwards compat with v0.2.x configs.

### 14.3 Wire-format compatibility (verified)

We do not bump `PROTOCOL_LABEL` for this. The new fields in `SasEnrollInfo` are additive to an existing JSON envelope. The kotlinx.serialization Json instance preserves `encodeDefaults=true` (per `feedback_kotlinx_serialization_defaults`). Older daemons/apps ignore unknown JSON fields per Kotlin/Python natural extensibility. The reserved bump for future structural changes is `b"wg-peerjs/v2/sigbox"`.


## 15. Migration and compatibility

### 15.1 Existing direct-WG tunnels keep working unchanged

A v0.2.10 joiner connecting to a v0.3.0 daemon, or vice versa, behaves identically to v0.2.x. The new fields are optional; absence triggers direct-mode-only logic.

### 15.2 Upgrading a tunnel to support obfuscation

Admin issues `wireguardrtc --upgrade-peer <pubkey> --transports direct,masque,wss`. Daemon:
1. Generates or rotates the peer's `enrollment_nonce`.
2. Derives the URL token from `url_token_root_key` + pubkey + nonce.
3. Updates `peers.d/<label>.conf` with `Transports = ...` and `EnrollmentNonce = ...`.
4. Pushes peer state to relay via control socket.
5. Marks SAS payload as stale; on next pairing the joiner gets the updated `endpoints` and `url_token`.

Between the upgrade and the re-pair, the joiner is unaware of obfuscation modes and continues to use direct. Tunnel never drops.

### 15.3 Downgrade

`wireguardrtc --downgrade-peer <pubkey> --transports direct`. Removes the `Transports = masque, wss` entries. Relay drops the peer's localhost socket allocations on next reconciliation. Re-pair completes the SAS payload change.

### 15.4 Daemon migration (new host, same WG private key)

When the daemon's WG private key is preserved across a migration (admin restored from backup), the question is whether URL tokens survive. **They do**, if and only if `/etc/wireguardrtc/url-token-root.key` is also restored. Backup/restore guidance: include the entire `/etc/wireguardrtc/` directory and `/var/lib/wireguardrtc-relay/` for full continuity. If either is lost, all peers must re-pair (the SAS round trip rebuilds tokens and fingerprints).

### 15.5 Concurrent connections from the same peer (during roam)

A joiner roams WiFi→cellular while a MASQUE tunnel is up. The new MASQUE connection (from cellular) reaches the relay; the old one (from WiFi) hasn't yet timed out. Policy:

1. New auth succeeds (URL token valid).
2. Relay accepts the new QUIC session and stores a reference to it.
3. The new session's first WG datagram is delivered through the per-peer localhost socket.
4. Kernel WG sees the latest endpoint (the relay's localhost port is stable; kernel WG doesn't see the public-side roam).
5. Relay tears down the old QUIC session after a short grace (1s) — both sides may have in-flight packets.

Direction-specific semantics:
- **Joiner → host** (receive direction at relay): both old and new outer sessions can deliver inbound WG datagrams into the per-peer localhost socket during the grace window. Kernel WG handles dedup at the WireGuard replay-window layer; spurious packets are dropped silently.
- **Host → joiner** (send direction at relay): the relay forwards the kernel WG response through the **most recently authenticated** outer session. The old session sees no outbound traffic during the grace; the new session sees everything. Effectively last-writer-wins for send.

The wg-protocol re-handshake (if WG decides to reauth) carries on through the new session.

### 15.6 Legacy WG tunnels (no wgrtc on the peer's side)

Legacy wg-quick peers without wgrtc software keep using direct kernel WG on the daemon. No `Transports` line in their drop-in config; treated as direct-only. Coexist on the same daemon; the relay never touches them.


## 16. Operational concerns

### 16.1 Admin debugging

New CLI subcommand: `wireguardrtc --debug-peer <pubkey>`. Output:
- Current `Transports` line and `EnrollmentNonce`.
- Last 10 connection attempts via the relay (timestamp, source IP, transport, result, error).
- Last 10 auth failures involving this peer's token (truncated paths only — never the full token in output).
- Current relay socket binding (`127.0.0.1:<port>`).
- Current QUIC parameters advertised by the relay.
- Time since last successful handshake.

### 16.2 Log volume

- `/var/log/wireguardrtc-relay.log`: 10 MB cap before rotation, 5 keep, gzip on rotate.
- Logged via `journald` by default; logrotate config provided for non-systemd setups.

### 16.3 Resource limits

- `LimitNOFILE=65536` per relay process.
- `MemoryHigh=512M`, `MemoryMax=1G` (systemd cgroup) — relay's RSS in our tests should be ~50-100 MB for 100 peers; 1G is a hard ceiling.
- Max peers per relay: 2048 (configurable in `/etc/wireguardrtc/relay.conf`).

### 16.4 Systemd ordering

```
# /lib/systemd/system/wireguardrtc-relay.service
[Unit]
After=network-online.target wireguardrtc.service
Requires=wireguardrtc.service
PartOf=wireguardrtc.service

[Service]
Type=notify
User=wireguardrtc-relay
Group=wgrtc-shared-secrets
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/wireguardrtc-relay /run/wireguardrtc-relay
LimitNOFILE=65536
MemoryHigh=512M
MemoryMax=1G
ExecStart=/usr/sbin/wireguardrtc-relay
Restart=on-failure
RestartSec=2
```

The relay starts after the daemon (it needs the control socket and URL-token key to be ready). `PartOf` means daemon-stop also stops the relay. `Restart=on-failure` recovers from crashes.

### 16.5 Distro packaging

We ship two `.deb` packages:

- `wireguardrtc` (existing, `Arch: all`, Python) — depends only on Python + PyNaCl. Unchanged.
- `wireguardrtc-relay` (new, `Arch: amd64 arm64 armhf`, statically-linked Go binary) — recommends `wireguardrtc`. Admin can install the daemon alone for direct-only deployments. `armhf` covers older Raspberry Pi / SBC deployments common in self-hosted setups; `arm64` covers modern ARM servers and Pi 4+.

Build invariants:
- `CGO_ENABLED=0` for the relay binary (truly static, no glibc dependency, deploys on any kernel ≥ Go's target). Verified at build time: `quic-go`, `masque-go`, `coder/websocket` have no cgo requirements.
- Go toolchain version pinned in `debian/rules`: `go ≥ 1.25` (matches quic-go master's `go` directive). Debian stable typically lags; we ship using a backported `golang-1.25` package or vendor a downloaded Go toolchain in the build environment.
- Vendored deps via `go mod vendor` checked into the repo, so Debian's no-network-at-build-time policy is satisfied. CI runs `go mod verify` to detect tampering.

### 16.6 RELEASING.md updates

Per `feedback_rebuild_artefacts_on_every_push`: every release now produces three primary artifacts (daemon .deb, relay .deb, Android .apk + .aab). RELEASING.md adds the relay-rebuild step. The shared GitHub release ships `.deb`s + `.apk` + `SHA256SUMS.txt`; the AAB stays local per `feedback_no_aab_in_github_releases`.

### 16.7 Cloudflare-fronted deployment (informational, not officially endorsed)

If an admin chooses to front the relay's WSS port via Cloudflare (against ToS as of Dec 2024), the deployment shape is:
- Relay configured with `--tls-passthrough` (no TLS on the relay itself; the front terminates TLS).
- `cloudflared` instance pointing the public DNS name at the relay's local port.
- Cloudflare proxies WS upgrades end-to-end.

This is documented for completeness but NOT in the official deployment guide. Admins use this at their own risk and responsibility. The recommended self-hosted equivalent is Caddy or HAProxy on a static-IP server.


## 17. Vulnerability handling

### 17.1 Tracking

The relay binary's dependencies (quic-go, masque-go, coder/websocket) have CVE histories. quic-go alone has shipped ~5 CVEs in 18 months (CVE-2024-22189, CVE-2024-45396, CVE-2024-53259, CVE-2025-29785, CVE-2025-59530). We treat upstream-CVE response as routine release work, not an emergency:

1. Subscribe to GitHub Security Advisories for the three repos.
2. Run `govulncheck` in CI on every push.
3. Pin and vendor dependencies; auto-PR on CVE detection.

### 17.2 Updating the relay binary

CVE in quic-go → upstream patches → we vendor the new version → build a new `wireguardrtc-relay` `.deb` → ship in a point release (e.g., v0.3.1).

**SLA**: we cut a `wireguardrtc-relay` point release within **2 weeks** of an upstream high-severity advisory in any vendored dependency. Lower-severity advisories ride along with the next scheduled release.

Admin updates via `apt upgrade wireguardrtc-relay`. systemd's `Restart=on-failure` means a single relay restart from a fresh binary picks up the fix; existing tunnels reconnect via auto-discovery.

For automated installs, the `apticron` / `unattended-upgrades` pattern suffices.

### 17.3 Communication

Security advisories for wgrtc itself (not upstream-only) get a `SECURITY.md` and a `GHSA-*` advisory on the GitHub repo. The Android app's Play Store listing gets a release note pointing at the advisory.


## 18. Implementation phases (rough)

Each phase produces a testable artifact. Order chosen so client and server roles co-evolve.

**Phase 1: Shared transport library.** `pkg/obftransport` under daemon tree; vendored into wgbridge_native. Defines `Transport`, `Listener`, `Dialer`, `PacketConn` interfaces with a loopback test transport. Pure-Go round-trip tests. ~1-2 weeks.

**Phase 2: MASQUE on daemon, both sides.** `obftransport.MasqueListener` and `MasqueDialer` using `quic-go/masque-go`. End-to-end Go test: in-process listener accepts in-process dialer; covers cert generation, URL token validation, decoy site. ~3-4 weeks.

**Phase 3: WSS on daemon, both sides.** Same shape with `coder/websocket`. ~2-3 weeks.

**Phase 4: Daemon-side relay process + integration.** Go binary, control socket, peers.d watcher, per-peer localhost socket allocation, glue to kernel WG. End-to-end: daemon-as-MASQUE-server accepts a connection from daemon-as-MASQUE-client on the same host. Real WG handshake completes. ~3-4 weeks.

**Phase 5: Android-side transport plugins, both sides.** Vendor obftransport, implement JNI surface for `MasqueDialer/Listener` and `WssDialer/Listener`. Single-tunnel PoC: Android-as-joiner dials daemon; daemon-as-joiner dials Android. ~4-6 weeks.

**Phase 6: Auto-discovery / fallback.** Happy-eyeballs scheduler on both sides. Cache, network_id, fail-fast invalidation. ~2-3 weeks.

**Phase 7: Signaling integration.** SasEnrollInfo extensions, joiner-side config plumbing, end-to-end pairing flow. ~2 weeks.

**Phase 8: Probing-resistance polish + operational story.** Decoy uniformity, log volume caps, debug commands, RELEASING.md update. Real-world probe testing. ~2 weeks.

**Out-of-scope for v0.3, tracked for future versions:**
- **v0.4+ MASQUE peer-to-peer NAT** (§10.7): simultaneous-QUIC handshake research. Opt-in via `Transports = masque-p2p` config flag. Defer until libp2p's work matures or we prototype something workable. Adds a `punch_endpoint` control-plane RPC.
- **v0.4+ Reality consideration** (§19): if GFW-bypass becomes a load-bearing user need.
- **v0.5+ JA3/JA4 mimicry, uTLS-for-QUIC**: revisit when libraries catch up.
- **v0.5+ ECH**: when both quic-go and Cloudflare's ECH infrastructure stabilize.

Total v0.3 ship target: ~5-6 months for Phases 1-8 (single-developer estimate; multi-developer can parallelize Phases 2+3 and 5+6). The direct-WG path remains stable throughout; we never have a "halfway broken" intermediate state.


## 19. Disregarded alternatives

**AmneziaWG.** Considered as the obfuscation layer instead of MASQUE/WSS. Rejected because: (a) even AmneziaWG 2.0 (released late 2025, broader rollout 2026-03) which adds Custom Protocol Signatures (CPS) with per-server randomization, still has a UDP-mimicry ceiling — "looks like *some* unknown UDP" is a strictly weaker position than "looks like HTTPS" against a probing observer; (b) doesn't help networks that block UDP entirely; (c) ongoing arms-race shape (CPS is dynamic noise, not protocol mimicry, so active probing can still distinguish from real HTTPS). Considered using it as a UDP-allowed fallback before WSS — rejected because adding a third transport with different operational characteristics adds complexity for marginal benefit over WSS on those networks. Worth revisiting **only** if MASQUE adoption gets blocked by something we didn't anticipate.

**Reality / VLESS / Trojan-Go.** Considered. Reality (Xray v26.2.4 / Reality-Vision, Feb 2026) is the current state-of-the-art in TLS-handshake mimicry against GFW, with reported ~98% bypass rate in active deployment. It works by impersonating a real external website's TLS handshake. **Honest framing**: Reality is strictly more effective against current GFW than our MASQUE/WSS will be. We choose MASQUE/WSS as a less-effective-but-standardized path for three reasons: (a) MASQUE is an IETF Standards Track protocol with no upstream-vendor risk, (b) impersonating a third-party site's TLS handshake is legally and ethically uncomfortable (the impersonated site has no consent in the matter and may be implicated in the user's traffic), and (c) integrating Reality would require a custom TLS stack on Android and the daemon — substantially heavier than wiring in MASQUE/WSS. Users who *specifically need* GFW bypass should use a dedicated Reality client today; we will revisit wgrtc-Reality compatibility for v0.4+ if it becomes a load-bearing user need.

**SSH tunneling.** Considered as a low-tech fallback. Sometimes works where TLS-mimicry doesn't because SSH is allowed for legitimate work. Rejected because: (a) SSH-as-VPN is a known fingerprint, (b) the SSH protocol's first bytes are recognizable, (c) adds another credential model (key pairs separate from WG keys), (d) WSS achieves similar "always-on TCP" properties with the TLS fingerprint as a bonus.

**Tailscale-style DERP relay.** Single static TLS+WebSocket relay; all clients NAT-traverse through it. Rejected because it doesn't fit wgrtc's P2P-without-central-relay model. Could be added as an opt-in "fallback relay" mode in the future for users who can't get any other transport to work, but not in v0.3.

**Hysteria 2 / TUIC / similar custom QUIC-over-UDP protocols.** Considered. Rejected because they're project-specific protocols (not IETF-standardized), at the mercy of one upstream maintainer's continued attention. MASQUE is the standardized answer; costs more upfront but doesn't depend on a single vendor.

**WireGuard-over-TCP via `tcp-wireguard` or similar.** Rejected because bare TCP wrappers around WG packets are trivially fingerprinted (no TLS handshake, packet sizes match WG). WSS does the same job but with real TLS.

**Shadowsocks-style stream-cipher obfuscation.** Rejected because shadowsocks is itself being detected and blocked; building on the same foundation would inherit the same arms race.

**Replacing kernel WG with userspace WG on the daemon for all modes (not just obfuscated).** Rejected for now because the cost (testing burden, performance regression risk) outweighs the benefit (architectural cleanup) when most users never notice. Revisit if performance becomes a non-issue or a security incident forces it.

**CONNECT-IP (RFC 9484) instead of CONNECT-UDP.** Rejected because WG is intrinsically UDP. CONNECT-IP's IP-frame tunneling adds unnecessary overhead and parsing complexity. Switch later if a use case demands IP-level transparency.

**Cloudflare Tunnel + native MASQUE reverse proxy.** Rejected because Cloudflare terminates TLS at the edge and doesn't relay CONNECT-UDP capsules end-to-end through their HTTP-aware reverse proxy. Cloudflare-fronted WSS works in principle (per §6.6) but is against current Cloudflare ToS and not officially endorsed.

**TCP fallback via `draft-ietf-httpbis-connect-tcp`.** Rejected for v0.3 because the draft isn't yet an RFC. WSS provides equivalent TCP-based functionality with a stable spec.

**Encrypted Client Hello (ECH).** Set aside for v0.3 because quic-go's ECH support is incomplete and the spec is still in flight. SNI mimicry with a plausible fake hostname is the v0.3 answer. Also: ECH on Cloudflare requires Cloudflare's cooperation (they hold the private key); not a unilateral capability.


## 20. Open questions

None at this revision. Two rounds of critical review (v1 → v2 → v3) closed all surfaced MUST-FIX and SHOULD-FIX items. Two genuinely-open decisions were resolved as committed scope:

- **MASQUE peer-to-peer hole-punching**: deferred to v0.4+ (§10.6, §10.7). v0.3 ships MASQUE with the constraint that the host has a reachable UDP port.
- **Reality-Vision integration**: disregarded for v0.3 (§19), reasoning made explicit. May reconsider for v0.4+ if GFW-bypass becomes a load-bearing user need.

Further open questions should be filed against this document via PR or commit message and tracked here.
