# Transport Obfuscation — Implementation Plan

**Companion to:** [`obfuscation-design.md`](obfuscation-design.md). The design doc
explains *what* and *why*; this plan explains *what to build first*, *what
"done" looks like at each step*, and *what depends on what*.

**Target release:** v0.3.0 (estimate: ~5–6 months single-developer; less in
parallel).

Track items here as a checklist. Each phase ships as a stable artifact so
v0.2.x users are never broken at HEAD.


## Phase 1 — Shared transport library

**Goal:** abstract `Transport` interface plus a loopback test transport. No
network code yet.

**Deliverables**
- [ ] New module `daemon/relay/obftransport/` (Go).
- [ ] `Transport`, `Listener`, `Dialer`, `PacketConn` interfaces.
- [ ] `LoopbackTransport` implementation for round-trip unit tests.
- [ ] Pure-Go test suite: dialer-to-listener-and-back, lifecycle, close
  semantics, concurrent close.
- [ ] Vendored into wgbridge_native's go.mod (build verified on both ABIs).

**Done when** `go test ./daemon/relay/obftransport/...` passes and the
loopback transport handles 10k concurrent goroutines without leaks.

**Estimate:** 1–2 weeks.


## Phase 2 — MASQUE listener + dialer (daemon-side)

**Goal:** MASQUE listener and MASQUE dialer that pass packets through
`obftransport.Transport`. No wgrtc-relay process yet; this is library work.

**Deliverables**
- [ ] `obftransport/masque/listener.go` — wraps `masque-go` `Proxy` +
  `ProxyConnectedSocket`. Accepts CONNECT-UDP sessions, hands the inner UDP
  flow back as a `PacketConn`.
- [ ] `obftransport/masque/dialer.go` — joiner-side. Constructs HTTP/3
  request with sentinel target values (per design §5.2), establishes
  CONNECT-UDP, returns a `PacketConn`.
- [ ] Decoy site handler (canonical 200/404 responses per design §8). Same
  file serves both MASQUE and WSS decoys; per-deployment uniformity.
- [ ] URL token verification — receives a 22-char base64url path segment,
  hashes it via BLAKE2b, constant-time-compare against a peer map.
- [ ] TLS cert auto-generation (ECDSA P-256, persisted to a path passed via
  config).
- [ ] Tests: in-process listener accepts in-process dialer; round-trip a
  WG-handshake-sized payload (148 bytes) and a larger payload (1200 bytes);
  reject unknown URL tokens; verify decoy site response is byte-identical.

**Done when** the in-process test passes and `govulncheck` is clean against
the pinned `quic-go` + `masque-go` versions.

**Dependency:** Phase 1.

**Estimate:** 3–4 weeks.


## Phase 3 — WSS listener + dialer (daemon-side)

**Goal:** parity with Phase 2 but for WebSocket-over-TLS.

**Deliverables**
- [ ] `obftransport/wss/listener.go` — `net/http` listener with `coder/websocket`
  upgrade handling. WS frames carry one WG datagram each.
- [ ] `obftransport/wss/dialer.go` — joiner-side. `coder/websocket` dial
  with TLS config matching the design's pinned/CA modes.
- [ ] Reuse the Phase 2 decoy site handler.
- [ ] Reuse the Phase 2 URL token verification.
- [ ] `--tls-passthrough` config flag for reverse-proxy-fronted deployment.
- [ ] Tests as Phase 2.

**Done when** in-process round-trip works for both pinned-cert and
CA-validated configurations.

**Dependency:** Phase 1 (Phase 2 can run in parallel with this once shared
decoy/auth code is factored out).

**Estimate:** 2–3 weeks.


## Phase 4 — Daemon-side relay process + integration

**Goal:** ship a `wireguardrtc-relay` Go binary that brokers between
obfuscated transports and kernel WG via per-peer localhost UDP sockets.

**Deliverables**
- [ ] `daemon/relay/cmd/wireguardrtc-relay/main.go` — entry point. Reads
  config, opens control socket, starts MASQUE and WSS listeners.
- [ ] Control socket protocol (design §11.3): `hello`, `list_peers`,
  `set_peers`, `peer_stats`, `cert_fingerprint`, `rotate_cert`. JSON-line.
  Reconciliation-based; SIGUSR1 triggers immediate sync.
- [ ] Per-peer localhost UDP allocator with persistence
  (`/var/lib/wireguardrtc-relay/relay-state.json`, flock-guarded).
- [ ] Python daemon side: `relay-client.py` module that watches `peers.d/`,
  sends `set_peers` on changes, sends SIGUSR1 to relay on peers.d writes,
  polls `peer_stats` for the existing 30s status loop.
- [ ] Python daemon: configures kernel WG with `endpoint = 127.0.0.1:<allocated>`
  for `masque`/`wss` peers.
- [ ] systemd units: `wireguardrtc-relay.service` per design §16.4.
  `wgrtc-shared-secrets` group setup in postinst.
- [ ] End-to-end test: spin up daemon + relay on same host. Add a peer with
  `Transports = masque`. Use a hand-rolled Go client to complete the MASQUE
  handshake and the WG handshake. Verify packets traverse end-to-end.

**Done when** the end-to-end test passes and `dpkg-buildpackage` produces a
clean `wireguardrtc-relay_X.Y.Z-1_amd64.deb`. Document the test in
`docs/obfuscation-runbook.md` (new).

**Dependency:** Phases 2 + 3.

**Estimate:** 3–4 weeks.


## Phase 5 — Android-side transport plugins

**Goal:** Android joiners can dial MASQUE/WSS; Android hosts can listen.

**Deliverables**
- [ ] Vendor `obftransport` into wgbridge_native (`android/wgbridge_native/go.mod`).
- [ ] JNI surface for `MasqueDialer.Connect(url, ...)`, `MasqueListener.Listen(...)`,
  `WssDialer.Connect(...)`, `WssListener.Listen(...)`. Each returns a handle that
  the existing wgbridge backend uses as the UDP carrier for wireguard-go.
- [ ] Per-accept `protect()` plumbing for WSS listener (design §12.4).
- [ ] AndroidManifest.xml migration to `specialUse` foreground service type
  with `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` justification (design §12.5). This
  is a one-way migration; remove `connectedDevice` reference.
- [ ] APK size measurement before/after.
- [ ] Real-device validation: emulator-as-joiner dials sandbox-as-host over
  MASQUE; ChromeOS-as-host accepts joiner connections over MASQUE.
  Equivalent matrix for WSS.

**Done when** an Android instrumented test (e.g.
`JoinerObfTransportTest`) handshakes through both transports end-to-end and
the `:app:assembleRelease` artifact stays under 50 MB per ABI.

**Dependency:** Phases 2 + 3 (the listener/dialer code is shared via Go
modules).

**Estimate:** 4–6 weeks.


## Phase 6 — Auto-discovery / fallback

**Goal:** joiner picks the working transport without user intervention.

**Deliverables**
- [ ] `obftransport/auto/scheduler.go` — happy-eyeballs scheduler per design
  §9. Stages: t=0 direct, t=100ms MASQUE, t=300ms WSS. 10s total timeout.
- [ ] Cache layer with `(tunnel_id, network_id, endpoints_hash)` key.
  Persisted to platform-appropriate storage (SharedPreferences on Android,
  `/var/lib/wireguardrtc/cache.db` on daemon).
- [ ] Network identity extractor per design §9.4 (Android: SSID hash + carrier +
  iface; Linux: gateway MAC + iface). BLAKE2b with local-only secret.
- [ ] Fail-fast invalidation: cached transport fails → invalidate
  immediately, re-probe.
- [ ] Tests: simulate selective transport failure (mock listener that 404s
  MASQUE but accepts WSS); verify fallback within 1 second; verify cache
  invalidation on policy change.

**Done when** unit tests demonstrate correct fallback under each of the
scenarios in design §3's threat-model table.

**Dependency:** Phase 5.

**Estimate:** 2–3 weeks.


## Phase 7 — Signaling protocol integration

**Goal:** end-to-end pairing flow with obfuscation-mode advertisement.

**Deliverables**
- [ ] `SasEnrollInfo.endpoints[]`, `endpoints_version`, `urlToken` fields
  (design §14.1). Backwards-compatible: v0.2.x payloads still parse.
- [ ] kotlinx.serialization `encodeDefaults=true` invariant test
  (`feedback_kotlinx_serialization_defaults`).
- [ ] Python daemon: emits new fields in SAS payload when peer has any
  non-direct transport. Wormhole-pairing CLI accepts a `--transports` flag.
- [ ] peers.d format: `Transports = ...` line orthogonal to existing
  `Mode = ...`. Default `Transports = direct` for backwards compat.
- [ ] Migration commands: `wireguardrtc --upgrade-peer <pubkey>
  --transports direct,masque,wss`; `--downgrade-peer`; `--rotate-peer-nonce`.
- [ ] End-to-end: pair Android-to-daemon over wormhole with `--transports
  masque`. Verify joiner uses MASQUE on first connect.

**Done when** the upgrade/downgrade CLI commands round-trip cleanly and the
joiner observably uses the advertised transports.

**Dependency:** Phases 4 + 5 + 6.

**Estimate:** 2 weeks.


## Phase 8 — Probing resistance polish + operational story

**Goal:** ship the deployment.

**Deliverables**
- [ ] Rate limiting per design §8.3 (three-tier: burst / sustained /
  /24-daily).
- [ ] Log volume caps (1 MB/min burst, 10 MB/day total, per-IP throttle).
- [ ] `wireguardrtc --debug-peer <pubkey>` subcommand (design §16.1).
- [ ] `RELEASING.md` updates: relay-rebuild step, dual-deb release.
- [ ] Real-world probe testing: deploy on a public IP, run a probe-sweep
  generator against it, verify uniform decoy responses, verify rate limits
  hold, verify no logs leak token material.
- [ ] User-facing docs: `obfuscation-runbook.md`, `README.md` update.

**Done when** the deployment guide is complete and a v0.3.0 release tag can
be cut.

**Dependency:** Phase 7.

**Estimate:** 2 weeks.


## Out-of-scope for v0.3 (tracked here so the doc lives one place)

- **v0.4+** MASQUE peer-to-peer NAT (design §10.7). Adds cross-process
  punch RPC.
- **v0.4+** Reality / VLESS reconsideration if GFW bypass becomes a load-
  bearing user need (design §19).
- **v0.5+** JA3/JA4 mimicry, uTLS-for-QUIC. Library-availability gated.
- **v0.5+** Encrypted Client Hello. Library + Cloudflare gated.


## Cross-cutting work that doesn't belong to a single phase

- [ ] CVE handling (design §17): `govulncheck` in CI, GitHub Security
  Advisory subscription, 2-week SLA on relay point-release after high-
  severity upstream advisory.
- [ ] Documentation: every new file gets a header explaining design-doc
  cross-reference.
- [ ] Memory updates (`project_obfuscation_design.md`) as decisions firm
  up during implementation.


## Risk register

Three risks worth keeping an eye on; each has a fallback if it materializes:

1. **quic-go API churn between vendored version and master.** Mitigation:
   pin version, vendor, `go mod verify`. If a CVE forces an upgrade that
   breaks our integration, allocate ~1 week for adaptation.
2. **Android `specialUse` FGS type rejected by Play Store policy review.**
   Mitigation: write a strong justification (design §12.5). Fallback: file
   a Play policy clarification request; in the meantime ship via GitHub
   only.
3. **MASQUE adoption blocked on a network we test against (active QUIC
   blocking, anti-h3 fingerprinting).** Mitigation: this is exactly why
   WSS fallback exists. If WSS *also* blocked, escalate to Reality
   reconsideration per design §19.
