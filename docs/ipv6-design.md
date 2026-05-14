# IPv6 Support — Design Document

**Status:** Draft, planning phase.
**Author:** wgrtc developers (this doc lives alongside the code).
**Scope:** What it would take to make wgrtc work end-to-end on IPv6, both as a publisher (host) and as a subscriber (joiner), on both the Python daemon and the Android app.

This is a living document.  As implementation progresses, each section should be updated with "what we found when we built this" notes.  Bake new edge cases into the test suite first, then update prose here.


## 1. Why this is worth doing

1. **IPv6-only networks exist.**  T-Mobile (US) cellular gives Android devices IPv6-only by default with 464XLAT for v4-only apps.  A wgrtc joiner on T-Mobile that wants to reach a dual-stack host should not depend on 464XLAT or relay.
2. **IPv6 typically doesn't NAT.**  The most painful part of wgrtc — the raw-IP-injection hole-punching dance — is unnecessary in pure-v6 environments.  Direct UDP connect works.  That's a *simpler* code path, not a harder one, once we wire it up.
3. **Dual-stack hosts already get half-working v6 today** (PS19 dual-stack STUN parsing, PS24 endpoint bracketing, D2 per-family NAT classifier).  The remaining work is closing the loop so v6 isn't accidentally dropped along the way.


## 2. Working principles

### 2.1 No grand new protocol version

The signaling wire format already accepts addresses as opaque strings.  `assigned_address`, `wg_endpoint`, and `allowed_ips` in `SasEnrollInfo` are strings.  wg-quick's own config accepts comma-separated dual-stack values (`Address = 10.99.0.2, fd00::2`, `AllowedIPs = 0.0.0.0/0, ::/0`).  We piggyback on that — **no protocol-version bump required** unless we hit a structural roadblock.

If we need to bump it (e.g., to add explicit per-family slots for IPv6-only enrolment), we go to `PROTOCOL_LABEL = b"wg-peerjs/v2/sigbox"`.  Keep that option in reserve.

### 2.2 Hole-punching stays IPv4-only

Per `CLAUDE.md` §7 and confirmed by audit: `inject_raw_udp()` uses `AF_INET + IP_HDRINCL` and constructs IPv4 headers.  Replicating this for IPv6 requires `AF_INET6 + IPV6_HDRINCL` plus a v6 header build, and on most v6 paths it isn't useful because there's no NAT pinhole to keep warm.  We accept this asymmetry: **v4 path uses raw inject; v6 path relies on the kernel WG handshake initiating a v6 connection directly to the advertised endpoint.**

If a deployment turns out to have v6-NAT (NAT66 or a misbehaving CGNAT) and needs hole-punching, that's a future scope decision (see §9).

### 2.3 Discover, don't assume

Several "is v6 reachable?" questions can't be answered statically:
- Does the host's external network actually carry GUA traffic?  (STUN-over-v6 tells us.)
- Does the joiner's network reach `0.peerjs.com` over v6?  (TCP connect probe tells us.)
- What MTU does the path support?  (PMTUD is unreliable behind firewalls; we clamp conservatively.)

We **probe at startup and re-probe on network change** rather than reading config flags.  Existing helpers (`--check-nat`, the candidate-rank ladder) already follow this pattern; v6 just adds another rung.

### 2.4 Cross-family scenarios are explicitly out of scope (for now)

| Joiner | Host | Decision |
|---|---|---|
| v4-only | v4-only | Works today. |
| v4-only | v6-only | Out of scope — needs relay or NAT64.  Document; admin solves via dual-stack host. |
| v6-only | v4-only | Out of scope — same.  Joiner OS may synthesize NAT64 prefix but we won't promise it. |
| v6-only | dual-stack | Works after v6 work.  Joiner reaches v6 endpoint. |
| dual-stack | v4-only | Works today.  Joiner reaches v4 endpoint. |
| dual-stack | v6-only | Works after v6 work. |
| dual-stack | dual-stack | Happy-eyeballs prefers v6 per RFC 8305. |


## 3. Current state of play (post-audit, 2026-05-14)

Captured here so future readers can diff against §4.

### 3.1 Daemon (`daemon/wireguardrtc`)

**Already v6-aware:**
- STUN XOR-MAPPED-ADDRESS parsing (dual-family)
- NAT classifier (per-family verdicts, D2)
- AllowedIPs range parsing (`ipaddress` module)
- Wire-format strings are opaque

**v4-only:**
- Production STUN query (`stun_query()` returns single v4 address)
- Endpoint publication (only v4 endpoints make it onto the wire)
- Raw socket injection (intentional, accepted)
- `wake_via_iface()` (AF_INET + TEST-NET-1 bogon)
- `PublicIp` config (rejects v6 with explicit error)

### 3.2 Android app

**Already v6-aware:**
- STUN dual-stack parsing (PS19)
- Endpoint formatting (PS24 v6 bracketing)
- MTU math layer (`MtuMath.OuterFamily.{V4,V6}`)
- DNS proxy (handles A + AAAA)
- AllowedIPs accepts v6 strings

**v4-only:**
- gvisor netstack IPv4 NIC only — no v6 NIC code
- Host endpoint candidate selection ranks v4 only
- Catchall TCP/UDP/ICMP forwarders are masquerade-NAT, IPv4 only
- MTU default hardcoded for v4 outer (1420)


## 4. Target architecture

### 4.1 Host (daemon side)

1. **Listen-port reuse for v6.**  WireGuard's `wg set wgN listen-port` already accepts a single UDP port that bind to both v4 and v6 wildcard sockets.  Confirm with `ss -ulpn` that we see `*:51820` and `[::]:51820`.
2. **STUN-over-v6 in `stun_query`.**  When the iface has a public v6 address (not link-local, not ULA), open a second STUN connection over `AF_INET6` and record the result as a separate candidate.  Use the same upstream STUN-server list (most STUN servers are dual-stack).
3. **Dual-stack endpoint advertisement.**  `discover_local_candidates()` returns a list; today every entry is v4.  Add v6 entries when discovery succeeds.  The wire format already carries multiple candidates.
4. **`PublicIp` accepts either family.**  Remove the rejection, document that a comma-separated `PublicIp = 203.0.113.5, 2001:db8::5` form covers dual-stack.  (Alternate: `PublicIp4 = … / PublicIp6 = …` for clarity; bikeshed.)
5. **Host-mode v6 mesh address.**  Convention: derive a ULA `/64` from `BLAKE2b(WG-pubkey, label="wgrtc/v6-mesh")[:8]` mapped into `fd00::/8`.  This gives every host a deterministic, collision-resistant v6 prefix without admin config.  Joiners get a `/128` inside that.
6. **No hole-punching for v6 peers.**  Skip `inject_raw_udp` + `wake_via_iface` when the active endpoint is v6.  The kernel WG module dials directly.

### 4.2 Joiner (daemon CLI + Android app)

1. **Accept v6 endpoints in `--use-wormhole` output.**  The wg-quick config printed by the joiner CLI already supports v6 endpoints via correct bracketing; just make sure the daemon publishes them.
2. **Joiner-side broker reachability over v6.**  When dialling `wss://0.peerjs.com/peerjs`, Android's networking stack honours happy-eyeballs.  Smoke-test on a v6-only network (T-Mobile, or a NAT64-only emulator config).
3. **Android: ensure v6 isn't dropped at the joiner's VpnService route table.**  `AllowedIPs = ::/0` needs an explicit `addRoute(IPv6.ANY, 0)` call on `VpnService.Builder`; check it's there.
4. **Android joiner `pickHostEndpoint`.**  Accept v6 candidates from the host's enrolment payload; don't filter on family.  Currently filters live in `IfaceCandidates`; widen them.

### 4.3 Host-mode (Android-as-host)

This is the heaviest leg.  Mode A host uses gvisor netstack to receive joiner traffic and forward to the underlying ChromeOS network.  Adding v6:

1. **gvisor v6 NIC.**  Add an IPv6 protocol stack to the existing netstack.  `tcpip.AddProtocolAddress` for the synthetic ULA + a routable v6 if available.
2. **v6 catchall forwarders.**  TCP and UDP forwarders today masquerade via per-flow OS sockets.  v6 forwarder is similar but does NOT need NAT — IPv6 typically uses route forwarding.  Architecture: a separate `v6ForwardingHook` that just relays packets out the underlying interface.  Less code than the v4 forwarder, because no source-NAT step.
3. **DNS proxy AAAA upstream.**  Already responds to AAAA queries.  Confirm the upstream resolver is reached over the underlying network with `Os.socket(AF_INET6, …)` when v6 is preferred.
4. **MTU.**  When the host advertises a v6 endpoint, use `OuterFamily.V6` (40-byte overhead instead of 20).  When dual-stack, take the minimum.

### 4.4 Configuration knobs

We try to keep these to a minimum.  Defaults should "just work" when v6 is available; admins toggle only when defaults are wrong.

```ini
[Global]
# IPv6 endpoint publication (default: yes if STUN over v6 succeeds).
# Set "no" to disable v6 even when the OS has v6 connectivity.
EnableIPv6 = yes

# Comma-separated list of static public IPs.  Either family.  When
# set, overrides STUN discovery for that family only — STUN for the
# other family still runs.
# PublicIp = 203.0.113.5, 2001:db8::5

[Stun]
# Same Servers = list works for both families; STUN servers that
# resolve to both A + AAAA are queried over both.
```

No new section, no new wire fields.

### 4.5 Wire-format compatibility matrix

`SasEnrollInfo`'s string fields can already carry dual-stack:

| Field | Form |
|---|---|
| `assigned_address` | `"10.99.0.2"`, `"fd00::2"`, or `"10.99.0.2, fd00::2"` |
| `allowed_ips` | `"10.99.0.0/24"`, `"::/0"`, or `"0.0.0.0/0, ::/0"` |
| `wg_endpoint` | `"203.0.113.5:51820"` or `"[2001:db8::5]:51820"` |

Pre-v0.2.5 daemons / pre-v0.2.5 apps that don't understand the second list element will gracefully degrade — they'll parse the first and ignore the comma+rest, OR they'll error.  Need to test which.  If they error, we bump to v2 protocol label.


## 5. Edge cases to test

In rough order of nastiness:

1. **MTU mismatch.**  Joiner's outer is v6 (1280-byte path MTU on some mobile networks), inner is v4 (1500 inside the tunnel) — fragmentation across reality.  Test path: v6-only joiner → wgrtc tunnel → IPv4 web server, fetch a 100 KB file, verify no truncation.
2. **Privacy addresses (RFC 4941).**  Host's outer v6 address rotates every hour.  Daemon's STUN poll cadence (30 s) catches this; the joiner gets updated candidates via signaling.  Test by manually rotating the host's IPv6 privacy address and observing the joiner's `wg show` endpoint update.
3. **Link-local (`fe80::/10`) leakage.**  Never advertise.  Test: enumerate local addresses on a network where link-local is the only available v6 (interface UP, no SLAAC), confirm we don't put `fe80::…` on the wire.
4. **ULA-only host (`fd00::/8`).**  Some home networks have ULAs only, no GUA.  Adversary case: ULA in `[Peer] Endpoint` only works if the joiner can route to it — which over the open internet, they can't.  Test: host with only ULA → joiner refuses to use that endpoint, falls back to v4.
5. **Scope IDs in link-local.**  We never advertise link-local so this is moot, but the parser should reject them defensively.
6. **NAT64 (`64:ff9b::/96`).**  v6-only joiner on a NAT64 network reaches a v4 host endpoint by synthesizing `64:ff9b::cb00:7105` for `203.0.113.5`.  Native OS handles it; we do nothing.  Test: v6-only Android emulator → v4 host endpoint, verify handshake completes.
7. **Dual-stack happy-eyeballs.**  Joiner has both v4 and v6 paths to the host.  Per RFC 8305 prefer v6 with a 250 ms head start.  Today wireguard-go won't switch endpoints mid-tunnel; the joiner picks one at handshake time.  Test: candidate race must rank v6 candidates ahead of v4 when both reachable.
8. **WireGuard PersistentKeepalive over v6.**  Same 25 s default; verify packets land.  Test in `wg show wgN latest-handshakes` after 30 s idle.
9. **Joiner roams from v4 wifi to v6-only cellular.**  Endpoint must update.  Existing roam mechanism (PS13) re-races candidates; v6 must be in the race set.
10. **Broker (`0.peerjs.com`) reachability over v6.**  Check AAAA record: `dig AAAA 0.peerjs.com`.  Cloudflare-fronted, so dual-stack is overwhelmingly likely but not guaranteed.  Fall back to v4 if broker is v4-only.
11. **Endpoint port in IPv6.**  Some firewalls block v6 UDP entirely.  Distinct failure mode from "no v6 connectivity".  STUN-over-v6 succeeds (TCP/443 to broker), but WG handshake fails.  Hard to distinguish from MTU issues; document.


## 6. Test surface

### 6.1 Daemon (Python, `daemon/tests/`)

- `tests/<NN>_stun_v6.py` — STUN over IPv6 returns a v6 candidate when the host has GUA connectivity (uses the container at 10.10.0.122 which has GUA).
- `tests/<NN>_publicip_dual_stack.py` — `PublicIp = 203.0.113.5, 2001:db8::5` validates and produces both candidate entries.
- `tests/<NN>_endpoint_publication_dual_stack.py` — `discover_local_candidates()` returns v4 + v6 when both exist.
- `tests/<NN>_wormhole_pair_v6_endpoint.py` — wormhole pair where the host advertises a v6 endpoint; joiner CLI prints a `[v6]:port` form.
- `tests/<NN>_hole_punching_skipped_for_v6.py` — verify `inject_raw_udp` and `wake_via_iface` are NOT invoked when the active endpoint is v6.

### 6.2 Android (`app/src/test/` JVM, `app/src/androidTest/` instrumented)

- `test/<…>/IpV6EndpointBracketingTest.kt` — `formatEndpoint("2001:db8::1", 51820)` → `"[2001:db8::1]:51820"`. (Probably already exists; regression-pin.)
- `test/<…>/CandidateRankV6Test.kt` — happy-eyeballs ordering when both families present.
- `test/<…>/MtuMathV6Test.kt` — `OuterFamily.V6` produces 1400-byte MTU; dual-stack outer takes the minimum.
- `androidTest/<…>/V6DnsProxyTest.kt` — DNS proxy AAAA query, verify response uses v6 transport upstream.
- `androidTest/<…>/V6JoinerVpnRoutingTest.kt` — `AllowedIPs = ::/0` installs a v6 default route in the tun (use `IpRoute.list()` to verify).

### 6.3 Cross-cutting (real-device)

- v6-only joiner reaches dual-stack host (T-Mobile or NAT64-only emulator config — needs lab setup).
- Privacy-address rotation on host doesn't break the tunnel (host's outer v6 changes; joiner's `wg show endpoint` should update within one daemon poll cycle, ≤30 s).
- ULAs are NOT advertised externally.


## 7. Roll-out plan

In dependency order (each step depends on the previous compiling + tests passing):

| Step | Scope | Layer | Test gate |
|---|---|---|---|
| **V6.0** | This design doc | docs | review |
| **V6.D1** | Daemon: STUN over v6 in production `stun_query` | daemon | `tests/<NN>_stun_v6.py` |
| **V6.D2** | Daemon: `PublicIp` dual-stack | daemon | `tests/<NN>_publicip_dual_stack.py` |
| **V6.D3** | Daemon: candidate publication includes v6 entries | daemon | `tests/<NN>_endpoint_publication_dual_stack.py` |
| **V6.D4** | Daemon: skip hole-punch for v6-active peers | daemon | `tests/<NN>_hole_punching_skipped_for_v6.py` |
| **V6.A1** | App: candidate-ranker accepts v6, ranks per RFC 8305 | android JVM | `CandidateRankV6Test.kt` |
| **V6.A2** | App: joiner VpnService installs `::/0` route when AllowedIPs has it | android instrumented | `V6JoinerVpnRoutingTest.kt` |
| **V6.A3** | App: MTU defaults adjust for v6 outer | android JVM | `MtuMathV6Test.kt` |
| **V6.H1** | Host-mode: gvisor IPv6 NIC | android instrumented | `V6HostNicTest.kt` |
| **V6.H2** | Host-mode: v6 catchall forwarders | android instrumented | `V6HostForwarderTest.kt` |
| **V6.H3** | Host-mode: DNS proxy v6 upstream | android instrumented | `V6DnsProxyTest.kt` |
| **V6.E2E** | End-to-end on real hardware | manual + harness | real-device matrix |
| **V6.DOC** | Documentation sweep + memory updates | docs | review |

**V6.D1-D4 are the canonical "make daemon dual-stack" pass.**  V6.A1-A3 are the corresponding joiner-app pass.  V6.H1-H3 (Android-as-host) is a separate, heavier deliverable that can ship in a later release if needed.


## 8. Open questions / decisions to make as we go

1. **Single `PublicIp` accepting comma-separated, or split `PublicIp4` / `PublicIp6`?**  Comma-list is more compact; split is clearer.  Lean toward `PublicIp` accepting a list, mirroring `Address` in wg-quick.
2. **ULA derivation:** is `BLAKE2b(pubkey, label="wgrtc/v6-mesh")[:8]` enough?  Or should it be `[:5]` to leave the user 3 bytes of subnet?  ULA RFC 4193 mandates `fd` + 40-bit random.  We have 40 bits to play with.  Use them all for the random part: `fd + 40-bit hash` → `/48` per host, leaving `/64` subnets free.
3. **What does the daemon do on a host that has v6 routes set up but the routes don't actually work?** (Carrier-grade IPv6 with broken connectivity.)  STUN-over-v6 returns failure → don't advertise v6.  But what if v6 STUN times out specifically?  Treat as no-v6 with a journal note.
4. **Joiner CLI: when the host advertises both v4 and v6, which does the joiner pick?**  The joiner's wg-quick output puts the host's `Endpoint` line as a SINGLE entry (kernel WG accepts one endpoint).  Pick v6 first (RFC 8305), with v4 as a fallback the daemon can switch to via signaling if v6 handshake fails.
5. **`AllowedIPs = ::/0` for joiners:** does the joiner need to ALSO have `AllowedIPs = 0.0.0.0/0`?  Almost always yes for full-tunnel; document that "::/0" alone is unusual.


## 9. Future / out-of-scope (for now)

- **v6 hole-punching.**  Requires `AF_INET6 + IPV6_HDRINCL` raw socket + v6 header builder.  Probably needed once we see CGNAT-v6 in the wild.  Code skeleton would mirror `inject_raw_udp` v4 path.
- **v6 multicast / mDNS through tunnel.**  Currently NAT-masquerade-only catchall doesn't carry multicast.  v6 path *could* relay link-local multicast (e.g., `ff02::fb` for mDNS) if we wanted "local-network through-tunnel" feature parity with `Mode A`.  Hard scope.
- **Cross-family bridging.**  v4-only joiner needs to reach a v6-only host: would require a NAT64/DNS64 relay.  Out of scope; document.
- **HE.net / tunnelled v6.**  Hosts that get v6 via a 6in4 tunnel have v6 with high RTT and small MTU.  Treat as "regular v6 + clamp MTU lower"; no special logic.


## 10. Implementation log

(Filled in as work progresses; one entry per finding.)

### V6.0 — 2026-05-14

Initial draft.  Audit complete.  Plan locked in: piggyback on existing string-typed wire fields; no protocol version bump; hole-punching stays IPv4-only; daemon-side dual-stack is the first deliverable.  Container 10.10.0.122 has GUA + ULA v6 (`2001:5a8:4cea:cc00::/64` + `fd00:a771:c05::/64`) and is the canonical v6 test host.

### V6.D1 — 2026-05-14

Done.  `stun_query(server, family=…)` now accepts AF_INET or AF_INET6 and behaves correctly for either.  Added `get_public_ips_all(stun_servers, state)` returning `[(family, ip), …]` — dual-stack candidate enumerator with strict-mode filtering, `PublicIp` comma-separated override, and per-family logging.

**Latent bug discovered during the work:** the production `stun_query` had its OWN inline STUN response parser that only matched `family == 0x01` (IPv4); the shared `_parse_stun_xor_mapped` function (which knows both families) was only called from the `--check-nat` path.  So before this change, a v6-aware STUN response sent by a public dual-stack server was silently dropped by `stun_query` even when the socket was set up correctly.  Fix: delegated the response parse to `_parse_stun_xor_mapped`.  6/6 V6.D1 tests pass on the dev box (which has GUA v6); other STUN regression tests stay green.

Files: `daemon/wireguardrtc` (refactor + new helper), `daemon/tests/52_stun_query_v6.py` (6 tests).

### V6.D3 — 2026-05-14 (jumped V6.D2 — it's subsumed)

`discover_local_candidates` now defaults its `stun_provider` to `get_public_ips_all` and accepts both the legacy flat-list form (back-compat with all 20 pre-existing tests) and the new `(family, ip)` tuple form.  Added `_is_candidate_eligible_v6` filter — drops v6 loopback, link-local, multicast, unspecified, and v4-mapped (the latter should travel as their v4 form, not as a v6 candidate; admins running ULA-only meshes inside their network keep ULA candidates so internal-only deployments still work).

PublicIp now accepts comma-separated dual-stack values: `PublicIp = 203.0.113.5, 2001:db8::5` publishes both families.  Subsumes the originally-planned V6.D2 (PublicIp dual-stack) — the helper change covered it.

7/7 V6.D3 tests pass; 20/20 pre-existing candidate-enumerator tests stay green.  No iface-enumeration v6 path yet — STUN-derived v6 candidates suffice for the common case (host has a routable GUA and STUN tells us the public mapping).  Local v6 iface enumeration is a future enhancement (V6.D4?) if we want the LAN-rank-50 equivalent on v6 networks.

Files: `daemon/wireguardrtc` (eligibility helper + dual-stack PublicIp/STUN paths), `daemon/tests/53_candidate_v6.py` (7 tests).

### V6.D4 — 2026-05-14

Local v6 iface enumeration.  Added `_enumerate_iface_addrs_v6`: shells out to `ip -6 -o addr show` and falls back to a pure-stdlib parser of `/proc/net/if_inet6` when `ip` is missing or returns empty.  The fallback parser is exposed as `_parse_proc_if_inet6(text) -> [(iface, ip), …]` and is tested directly with synthetic kernel output.  Scope filter: only `00` (global = GUA + ULA) is kept; link-local (`20`), host (`10`), site (`40`) are dropped.

`discover_local_candidates` now takes an `iface_addrs_v6_provider` kwarg and emits v6 ifaces at rank 55 (LAN equivalent for v6, just below v4 LAN at rank 50 — small bias toward v4 in mixed environments until we have happy-eyeballs data; tune later).  Advertise/suppress/own-wg gates apply to both families.

**Regression test fix:** `tests/27_candidate_enumerate.py`'s `discover()` helper previously didn't stub the new v6 provider; the production default reads `/proc/net/if_inet6` and on the dev box that pulled in 7 real GUA + ULA addresses, breaking the v4-focused expectations.  Added a `iface_addrs_v6=None` parameter (defaults empty), all 20 pre-existing tests pass again.

Files: `daemon/wireguardrtc` (enumerator + parser + dispatch), `daemon/tests/54_iface_v6.py` (7 tests), `daemon/tests/27_candidate_enumerate.py` (test-helper update).

### V6.D5 — (next)

Skip hole-punching for v6-active peers.  `inject_raw_udp` + `wake_via_iface` are v4-only; calling them with a v6 endpoint either errors or no-ops.  Plan: detect the active endpoint's family before invoking, skip the raw-inject leg for v6 endpoints, log a one-shot informational line.
