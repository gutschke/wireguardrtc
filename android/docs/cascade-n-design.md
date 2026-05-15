# Cascade-N Design — D4 phase 2

> Status: **DRAFT — awaiting user confirmation on scope interpretation.**
> Author: agentic / supervised
> Last touched: 2026-05-14

## Background

D4 phase 1 (host-N) shipped in commits `eea8e00..6ef5949`:

- `HostModeBackend` keeps a `ConcurrentHashMap<TunnelId, Slot>` of N
  independent wireguard-go bridges (`D4.H1`).
- `WgrtcViewModel.activeTunnelIds` is a unified flow of the joiner
  singleton plus the host set; per-tunnel `throughputFor(id)` /
  `peerStatsFor(id)` / `isActive(id)` flows are `WhileSubscribed`-cached
  (`D4.H2`).
- FGS notification body enumerates active tunnel names via BigText
  (`D4.H3`).
- `PortCollisionException` fail-fast at `HostModeBackend.start()`
  before wireguard-go's bind surfaces an opaque EADDRINUSE (`D4.H4`).
- Instrumented coexistence + collision tests under real JNI on
  x86_64 emulator and ARC ChromeOS (`D4.H5`).

The user signed off on phase 1 with the directive:

> *"option 2 [cascade-N] as not going to be used as often, but would
>  be a very real distinguishing feature and probably isn't as hard
>  to implement after all, considering our unique architecture. i
>  think we should give it a try after completion of option 1. start
>  by a detailed plan, risk assessment and maybe some prototypes to
>  confirm our assumptions."*

This doc is that plan.

## Scope interpretations — which "cascade-N" do we want?

The user's prior message clusters several adjacent ideas under
"cascade-N". I want to pick one before designing; the architectures
diverge enough that a wrong pick wastes weeks.

### Interpretation 1 — Multiple joiner tunnels on one device ("Joiner-N")

> N joiner-mode tunnels concurrently reachable. Phone connects to
> multiple remote networks at once.

- **Constraint**: Android caps the device at *one* `VpnService` at a
  time, system-wide. `VpnService.prepare(ctx)` returns one consent
  Intent; one `Builder.establish()` produces one TUN; a second call
  on a different `VpnService` subclass kills the first.
- This means joiner-N must share a single `VpnService` between N
  joiner wireguard-go devices — there's no kernel-level way around
  the cap.

### Interpretation 2 — Multi-hop cascade ("Cascade-N proper")

> One joiner tunnel relays for N host tunnels. The phone hosts N
> tunnels whose outbound traffic egresses via the joiner tunnel
> instead of the phone's OS network. Already-working `D3 — Validate
> two-tunnel cascading` is the *1-host-through-1-joiner* version of
> this; cascade-N generalises the host side.

- **Constraint**: today the host bridge's gvisor netstack egresses
  via OS sockets (`EgressSelector.socketFactory()` → JVM `Socket`).
  For cascade, those sockets need to ride the joiner's WG tunnel,
  i.e. their packets need to enter the joiner's kernel TUN instead
  of the OS routing table.
- The user already validated `D3`. Cascade-N is: "all N host tunnels
  cascade through the same single joiner."

### Interpretation 3 — Both 1 and 2 combined

> N joiner tunnels AND N host tunnels, with N×M routing flexibility.

- Architecturally a superset of 1 and 2. Probably too ambitious for
  one cycle.

### My read

The hint *"probably isn't as hard to implement after all, considering
our unique architecture"* points at **Interpretation 2** — the
existing userspace gvisor netstack is the natural place to route
host-side traffic through a joiner tunnel. Interpretation 1 would
require a major refactor of `JoinerVpnService` to be a multi-tenant
TUN, which our "unique architecture" doesn't particularly help with.

**Recommendation: confirm scope with user before writing more code.**

The rest of this doc assumes **Interpretation 2** unless otherwise
noted. Sections marked **[I1]** apply only to Interpretation 1.

## Today's joiner / host plumbing

```
                    +--- OS network ------------+
                    |                           |
   (kernel)         |                           |
+--TUN(joiner)--+   |  +-OS socket-+            |
|               |   |  |           |            |
|  wireguard-go |---+  |  protect()|            |
|  (joiner)     |      |  outbound |            |
+---------------+      +-----------+            |
                            |                   |
                            v                   |
                    +-- the wider internet -----+
                                ^
                                |
+-- gvisor netstack(host) --+   |  OS socket egress
|  wireguard-go(host)       |---+
|  Catchall TCP/UDP         |
|  Catchall ICMP            |
+---------------------------+
```

- Joiner: VpnService TUN → wireguard-go encrypts → OS UDP socket
  (`protect()`-ed) → wire.
- Host: gvisor netstack receives plaintext packets from joiners;
  every catchall forwarder opens a fresh OS socket via
  `EgressSelector` and writes the payload there.

**Cascade-N changes the second leg.** Host-side OS sockets need to
route through the joiner's WG tunnel instead of the phone's WAN.

## Cascade-N target architecture (Interpretation 2)

```
                    +--- OS network ------------+
                    |                           |
+--TUN(joiner)--+   |  +-OS socket-+            |
|               |   |  |           |            |
|  wireguard-go |---+  |  protect()|            |
|  (joiner)     |      +-----^-----+            |
+--^------------+            |                  |
   |    (3) cascade route    |  (1) joiner outbound
   |                         |
   |  (2) host gvisor egress |
   |                         |
+--+---- gvisor netstack(host N) ----+
|  wireguard-go(host)                 |
|  Catchall TCP/UDP routes through    |
|  → joiner TUN instead of OS         |
+-------------------------------------+
```

Path (2) → (3) is the new code:

1. Catchall forwarder receives plaintext from a host's joiner peer.
2. Instead of `socketFactory.createSocket(...)` (OS-rooted), the
   forwarder calls into a new `JoinerCascadeEgress` that:
   - Takes the destination IP + port + protocol.
   - Constructs a raw IP packet and writes it into the joiner's
     userspace netstack (or onto its TUN fd).
3. wireguard-go (joiner) encrypts and sends.

### Where the joiner's TUN fits

Two sub-options for path (3):

**Option A — Write directly to the joiner's TUN fd**

Bypass the cascade host's gvisor and write the packet directly to the
joiner's kernel TUN (the one the joiner's wireguard-go reads from).
Joiner's wireguard-go then matches the packet's destination against
its peer's AllowedIPs and encrypts.

Risks:
- Requires source-IP rewriting so the inner header looks like it
  comes from the joiner's interface address.
- Joiner-side reply packets land on the TUN with the joiner's
  interface IP as destination. We'd need to copy them back into the
  host's gvisor to deliver to the host's joiner peer.
- IPv6: the joiner's TUN might be v4-only or v6-only; cascade-N
  needs to handle mismatches gracefully.

**Option B — Cascade via the existing host-forwarder + a second
gvisor NIC bonded to the joiner's TUN**

Mirror the existing `host_forwarder.go` (V6.H2b ICMPv6 etc.) but
target NIC2 = joiner-TUN-backed instead of NIC2 = OS-route-backed.
The joiner's TUN fd is opened twice (once by wireguard-go via the
Android Builder, once by us via `dup()` for the gvisor side).

Risks:
- Double-open on a Builder.establish() TUN fd is undocumented.
  Needs spike to confirm Android lets us `dup()` and use the
  duplicate concurrently with wireguard-go reading the original.
- Synchronisation: both wireguard-go and our gvisor would be
  writing inbound bytes to the same TUN. Packet ordering / locking
  is delicate.

Option A is simpler if we accept the source-IP rewrite. Option B
keeps the architecture symmetric with through-host forwarder.

### Prototypes I want to run before committing

1. **`dup(TUN_fd)` smoke test** — call `Builder.establish()` from
   `JoinerVpnService`, immediately `Os.dup(pfd.fileDescriptor)`,
   write a hand-crafted IP packet to the dup'd fd, see if it shows
   up on the wire (encrypted by the joiner wg-go). 30-line spike
   in instrumented test. Decides Option A vs Option B.

2. **Inner-source IP rewrite** — verify that writing a packet whose
   source IP is `joiner.iface.address.0/32` actually elicits a
   correct reply path. The joiner host's WG peer needs to see
   "this is from my client" — if we use the joiner's own interface
   IP, replies come back to us; if we use the host-tunnel client's
   inner IP, the joiner-host peer needs that IP in its AllowedIPs.

3. **Cross-stack TCP handshake** — wire a single cascade flow
   through a unit/instrumented test rig: emulator hosts a host
   tunnel + joiner tunnel; a sandbox WG client connects to the
   host tunnel and tries to TCP-connect to an IP only reachable
   via the joiner. Pass = SYN reaches the joiner-side WG peer.

## Cascade-N target architecture (Interpretation 1, **[I1]**)

For completeness, Interpretation 1 ("multiple joiner VPNs on one
phone") would require:

- Subclass `VpnService` with a TUN configured for the union of all
  active joiner tunnels' AllowedIPs.
- Internal "joiner router" that:
  - Demuxes outbound packets from the TUN by destination IP →
    matches an active joiner's AllowedIPs → hands to that joiner's
    wireguard-go.
  - Multiplexes inbound packets from N OS UDP sockets back to one
    TUN (already true at the kernel level — TUN is one fd).
- Reconciler for AllowedIPs overlap: today
  `TunnelOverlapGuard.firstOverlap` refuses to bring up overlapping
  tunnels; would need to be relaxed for joiner-N or per-flow
  routing rules added.

Risk: this is a much bigger lift than Interpretation 2 and doesn't
benefit nearly as much from the existing userspace gvisor netstack
— it's net-new packet routing code at the VPN-edge layer.

## Risk register

| Risk | Severity | Mitigation |
|---|---|---|
| `dup(TUN_fd)` not allowed by Android security policy on some OEMs | Medium | Spike on x86_64 emulator + arm64 Pixel + ARC ChromeOS before committing |
| Inner-source-IP rewrite breaks reply-path | Medium | Test 3 above — early instrumented end-to-end before more code |
| MTU stacking eats payload (outer joiner WG ≈ 1380; cascade inner WG ≈ 1340) | Low | Already handled for V6 MTU; extend `MtuMath` to cascade case |
| Joiner tunnel goes down mid-cascade → all N host tunnels lose egress | High | Status banner on each host tunnel UI when cascading + joiner is down |
| Cascade introduces a routing loop (host tunnel's gvisor routes packet to its own joiner peer which routes back) | High | Strict AllowedIPs check + drop if dst ∈ host tunnel's own subnet |
| ChromeOS ARC's VpnService is per-applicationId; cascade between apps not possible | Low | Document, don't fix |
| `JoinerVpnServiceBinding` lifetime tied to single tunnel id today; cascade requires a long-lived joiner regardless of which host tunnels are up | Medium | Refactor `connectJob` / `disconnect(id)` paths so joiner stays alive for any active cascading host |
| Performance: every cascaded byte traverses gvisor twice (host stack + joiner stack) | Medium | Profile after first end-to-end works; userspace WG already has overhead so additive cost may be tolerable |

## Tasks I'd cut if we agree on Interpretation 2

- **D4.C1** — `dup(TUN_fd)` spike (instrumented test). Pass = JNI write to dup'd fd produces encrypted wire traffic.
- **D4.C2** — `JoinerCascadeEgress` interface + a NIC-2 wiring inside `wgbridge_native/host_forwarder.go`. Plumb a target-mode toggle: `NIC2_TARGET = os | joiner-fd`.
- **D4.C3** — Cascade routing config: per-host-tunnel "cascade through joiner X" setting in `TunnelStore`. Default off.
- **D4.C4** — Inner-source-IP rewrite in the cascade path.
- **D4.C5** — Status banner: host tunnel UI shows "cascading via {joiner name}" + warning when joiner is down.
- **D4.C6** — Routing-loop guard: refuse cascade when host tunnel's subnet overlaps the joiner's AllowedIPs.
- **D4.C7** — Instrumented end-to-end on emulator + ARC: sandbox WG client → emulator host tunnel → cascade → joiner → second sandbox WG client receives traffic.
- **D4.C8** — Real-device validation: Pixel as host+cascade, Chromebook as joiner upstream, sandbox as joining peer.

Estimated total: ~5–10 commits, mostly inside `wgbridge_native/`
and the host-side egress wiring. Joiner-side code change is small
(expose the TUN fd as an opaque write-target so wgbridge can hand
it to its host forwarders).

## Open questions for the user

1. **Scope:** Interpretation 1 (joiner-N) or Interpretation 2
   (cascade-N as I've described)? Or both?
2. **Joiner-side cooperation:** If Interpretation 2, do we want the
   user to mark a joiner tunnel as "available as cascade upstream"
   (opt-in toggle), or auto-discover from `AllowedIPs = 0.0.0.0/0`?
3. **Per-flow routing later?** Today we'd cascade entire host
   tunnels through one joiner; flow-level routing (some traffic via
   joiner, some via OS) is out of scope for this cycle but worth
   confirming the user agrees.
4. **MTU policy when cascading:** auto-recompute the cascading host
   tunnel's MTU floor to `1280 − wg-overhead − wg-overhead`? Or
   leave it to the user / tunnel author?

I'll wait for the scope confirmation before starting any prototypes.
