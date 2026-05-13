# wireguardrtc validation tests

These tests probe the assumptions the daemon depends on. They are designed to be
**safe to run on a live WireGuard server**: none of them modify any WireGuard
state, none touch your real WG listen port for raw injection, and the network
tests that go to public services (STUN servers, PeerJS broker) are brief and
single-shot.

Run order matters less than topic. Pick the tests relevant to your deployment.

| #  | Test                       | Privileges  | Touches network                | What it answers                                            |
| -- | -------------------------- | ----------- | ------------------------------ | ---------------------------------------------------------- |
| 01 | `01_stun_nat.py`           | none        | UDP to public STUN servers     | NAT type and whether it preserves source ports             |
| 02 | `02_port_bind.py`          | none*       | none                           | Is kernel WG's listen-port bind exclusive vs. share-able?  |
| 03 | `03_raw_inject.py`         | **sudo**    | one UDP packet to a STUN server| Does raw-inject from a "stolen" src port get a conntrack pinhole that return traffic uses? |
| 04 | `04_natpmp_pcp.py`         | none        | UDP to default gateway:5351    | Does the upstream router support NAT-PMP / PCP?            |
| 05 | `05_peerjs.py`             | none        | WSS to PeerJS broker           | Does our PeerJS protocol model match the broker's expectations?              |
| 06 | `06_ipv6_path.py`          | none        | UDP to public v6 endpoint      | Is direct IPv6 peer-to-peer feasible (no NAT to fight)?    |
| 07 | `07_wake_observe.py`       | **sudo**    | none                           | Read-only: what would `wake_tunnel` actually do per peer?  |
| 08 | `08_fabric_e2e.sh`         | none        | self-contained inside fabric   | End-to-end: two daemons + a local broker complete a WireGuard handshake through PeerJS signalling |
| 09 | `09_publicip.sh`           | none        | self-contained inside fabric   | Same as 08 but `[Global] PublicIp` overrides STUN; verifies the static-IP code path |
| 10 | `10_enroll_basic.sh`       | none        | self-contained inside fabric   | Auto-enrollment happy path: mint token → reference client enrolls → server provisions → ENROLL_OK |
| 11 | `11_enroll_race.sh`        | none        | self-contained inside fabric   | Single-use enforcement: two clients race for one token; loser receives authenticated `TOKEN_USED` |
| 12 | `12_enroll_replay.sh`      | none        | self-contained inside fabric   | Retry safety: legitimate retry with same keypair returns the cached `ENROLL_OK` envelope |
| 13 | `13_provision_broker.sh`   | none        | none (no fabric, no daemon)    | Stand-alone unit test of `wireguardrtc-provision-broker` validation + permit gating: 27 cases covering JSON malformation, iface/name/pubkey/token regex rejects, missing/expired/mismatched permits, happy path with space+apostrophe+Unicode names, single-use enforcement |
| 14 | `14_enroll_expiry.sh`      | none        | self-contained inside fabric   | Expired tokens silently ignored (no oracle for token existence); client sees timeout |
| 15 | `15_enroll_provision_fail.sh` | none     | self-contained inside fabric   | `ProvisionScript` exit ≠ 0 → authenticated `PROVISION_FAILED` response; token still consumed |
| 16 | `16_key_oracle.sh`         | none*       | none (unshare-only)            | Stand-alone test of `wireguardrtc-key-oracle`: byte-equality of derive_sigbox / derive_enroll vs in-process PyNaCl reference, set_endpoint applied to kernel, plus 11 reject paths covering iface/pubkey/token validation, loopback/link-local rejection, and refusal to silently create new peers (`peer-not-on-iface`) |
| 17 | `17_raw_helper.sh`         | none*       | none (unshare-only)            | Stand-alone test of `wireguardrtc-raw-helper`: 19 cases for inject (legit, src-port-mismatch, loopback/link-local/multicast/unspec/broadcast rejects, bad iface, traversal, missing port) and wake (legit, RFC-5737 catchall accepted, bad iface / no iface / junk IP / IPv6 rejects) plus unknown-op + malformed-JSON |
| 18 | `18_decrypt_caps.py`       | none        | none                           | Verifies the post-decrypt size caps in `decrypt_envelope` and `decrypt_enroll_blob`: legitimate sizes pass, b64-ciphertext over `MAX_*_CIPHERTEXT_B64` rejected, plaintext over `MAX_*_PLAINTEXT` rejected, non-string blob rejected |
| 19 | `19_stun_strict.py`        | none        | none                           | `[Stun] Strict = yes` test: loose mode (default) accepts private/CGN STUN responses for LAN deployments; strict mode rejects them and falls through to the next server, accepts globally-routable IPs (1.1.1.1 / 8.8.8.8), fails closed when all servers report private |
| 20 | `20_state_cleanup.py`      | none        | none                           | Auto-enrollment state lifecycle: `PendingTokensStore.purge_expired` drops expired tokens (kept) / kept-but-old (>24h consumed → dropped) / fresh ones (kept) and stale replay-cache entries; same-name re-mint supersedes the previous unexpired token in `PendingTokensStore.mint` and `remove_provision_permit` cleans up the corresponding broker permit file; broker opportunistically unlinks expired and malformed permit files on every request even when the request itself is rejected for an unrelated reason; `write_auto_active_peer` produces a peers.d-style drop-in with Mode=active and `load_peer_configs` merges that with the admin dir, with admin entries winning on PublicKey collision |
| 21 | `21_enroll_supersede.sh`   | none        | self-contained inside fabric   | Same-name re-mint: second `--enroll-token` for an unexpired pending name prints a supersede warning, removes the previous entry from `pending-tokens.json`, and the previous token's broker permit; the old token then enrolls as a silent timeout while the fresh one succeeds. |
| 22 | `22_auto_active_dropin.sh` | none        | self-contained inside fabric   | After ENROLL_OK fires, the daemon writes `<StateDir>/auto-enrolled.d/<label>-<fingerprint>.conf` carrying `Mode = active`.  Each fresh enrollment produces a new entry; re-writing the same pubkey is idempotent (same filename → overwrite, no accumulation).  This is the Phase-2 enabler that makes the daemon push signalling OFFERs to newly-enrolled peers without admin intervention. |
| 23 | `23_signal_wake.sh`        | none        | self-contained inside fabric   | Daemon's `metadata.kind = "signal_wake"` handler: a peer sends an empty-candidates wake; daemon decrypts, suppresses set_endpoint/raw_inject/wake (the wake claims no endpoint), and replies with a fresh OFFER bypassing the tunnel-already-UP guard. |
| 24 | `24_fast_wake.sh`          | none        | self-contained inside fabric   | End-to-end timing for `signal_wake`: round-trip completes in <5 s (well under the 30 s daemon poll cycle), the responsive OFFER's first candidate is the daemon's configured `PublicIp`. |
| 25 | `25_parallel_stun.py`      | none        | none (stubbed `stun_query`)    | Parallel STUN : `get_public_ipv4` fires all configured servers concurrently — slow servers no longer block fast ones — and `get_public_ipv4_all` returns a deduped list of every distinct reflexive address (multi-homed daemons get the full set in one round-trip). 15 cases covering parallel timing, dedup, strict-mode filtering, and PublicIp-override bypass. |
| 26 | `26_candidate_trim.py`     | none        | none                           | Sender-side per-peer deadlock trim : `filter_candidates_for_peer` drops candidates whose IP falls inside that peer's `AllowedIPs` before encryption.  Plus parsing for the new `[Global] AdvertiseInterfaces` / `SuppressInterfaces` conf knobs (consumed by Step C).  17 cases covering CIDR boundaries, multi-range union, malformed-entry resilience, and order preservation. |
| 27 | `27_candidate_enumerate.py`| none        | none (injected providers)      | Sender-side multi-candidate enumeration (Step C): `discover_local_candidates` builds the ranked list (PublicIp rank 0, STUN reflexive rank 10, physical/default rank 20, physical/non-default rank 30, bridge rank 40, RFC1918+CGNAT rank 50, allowlisted-mesh rank 60).  20 cases covering the rank table, hard drops (loopback/link-local/multicast/unspecified/RFC7335-CLAT/own-WG/suppress/tunnel-pattern), dedup with PublicIp+STUN, allowlist override of tunnel-pattern skip, list cap at 10, and integration with Step B's per-peer trim. |

\* `02_port_bind.py` uses `wg show` to discover live listen ports, which on
modern Ubuntu runs unprivileged but the WireGuard kernel module returns
`(hidden)` for some fields without `CAP_NET_ADMIN`. The bind probe itself is
unprivileged.

## Test fabric

`fabric.sh` and `stun_stub.py` are infrastructure used by the integration
tests, not standalone tests:

- **`fabric.sh`** — a tiny `unshare`-based test harness that spins up
  multiple isolated network namespaces inside an unprivileged user
  namespace.  Tests source it as a Bash library and call `fabric_*`
  functions to create hosts, link them with veth pairs, and run commands
  inside.  See the comment block at the top of the file for usage.
  Runs entirely as a regular user — no root, no Docker, no
  `systemd-nspawn`.
- **`stun_stub.py`** — a 50-line RFC 5389 STUN BINDING responder.  Used
  inside fabric tests where the namespaced hosts have no internet egress
  to reach a real STUN server.

## Dependencies

Standard Ubuntu, plus:

```bash
sudo apt install wireguard-tools conntrack
# python deps come with the daemon's venv; tests use only stdlib + websockets
```

For test 08, also install a PeerJS broker.  Either globally:

```bash
npm install -g peer
```

…or locally inside the `tests/` directory:

```bash
cd tests && npm install peer
```

The test auto-detects either layout, or accepts a `$PEERJS` override
pointing at any existing `peerjs` binary.

If a test needs a tool that isn't installed, it prints which package to install
and exits with code 2 (so a wrapper script can distinguish "missing dep" from
"actual failure"). Each test prints its own help with `-h`.

## Exit codes

- `0` — checks passed (or the test made an observation and reported it)
- `1` — a load-bearing assumption was refuted; daemon design needs rework
- `2` — environmental: missing tool, missing permissions, no network, etc.

## Interpreting results

The most actionable findings are:

1. **Test 01 verdict** — NAT type and port preservation. If symmetric or
   non-preserving, the daemon's hole-punch approach won't work on this
   network segment.
2. **Test 03 verdict** — raw-inject pinhole creation. If this fails, the
   entire hole-punch mechanism doesn't work on this host and you need an
   alternative (relay, NAT-PMP/PCP, or static port forward).
3. **Test 04** — if NAT-PMP or PCP is available, the daemon could use it
   instead of raw injection for a cleaner approach.
4. **Test 06** — if both peers have global IPv6, direct connectivity is
   possible without any NAT traversal.
5. **Test 08** — pre-flight regression check.  If the fabric e2e fails on
   a kernel where it used to pass, something downstream of the protocol
   has regressed (signalling round-trip, configuration parsing, lock
   handling, etc.).  The test takes ~15 seconds to run and is a good
   first thing to try when other tests behave unexpectedly.
