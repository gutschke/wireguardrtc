# Joiner-N + Cascade-N Design — D4 phase 2

> Status: **DRAFT — Option 1 primary; ready for review.**
> Author: agentic / supervised
> Last touched: 2026-05-15

## Background

D4 phase 1 (host-N) shipped in commits `eea8e00..6ef5949`:

- `HostModeBackend` keeps a `ConcurrentHashMap<TunnelId, Slot>` of N
  independent wireguard-go bridges (`D4.H1`).
- `WgrtcViewModel.activeTunnelIds` is a unified flow; per-tunnel
  `throughputFor(id)` / `peerStatsFor(id)` / `isActive(id)` flows
  are `WhileSubscribed`-cached (`D4.H2`).
- FGS notification body enumerates active tunnel names (`D4.H3`).
- `PortCollisionException` fail-fast (`D4.H4`).
- Instrumented coexistence + dual-stack inner-v6 tests under real
  JNI on x86_64 emulator and ARC ChromeOS (`D4.H5`).

Phase 2 generalises **joiner** tunnels to N concurrent, and layers
**cascade** routing on top of that for host tunnels that want to
egress via a joiner.

## Primary architecture — Joiner-N

> N joiner-mode tunnels concurrently active. Phone connects to
> multiple remote networks at once (home + work + hotel + …).

### The Android constraint, and why our existing stack absorbs it

Android caps the device at one `VpnService` system-wide. That cap
binds the *kernel TUN*, not our routing logic. We already have
every other piece we need:

- `wgbridge_native` runs wireguard-go in userspace-netstack mode
  (the existing `open(localAddr, mtu, listenPort)` path used by
  every host tunnel).
- gvisor handles IP routing inside our process today (host-side
  catchall + through-host forwarder, V6.H1/H2/H2b).
- N concurrent wireguard-go instances in one process is already
  validated — `twoHostTunnelsCoexistUnderRealJni` proves it on
  real JNI as of `6ef5949`.

So joiner-N is *one new wiring shape*, not new infrastructure:

```
                   apps
                    |
                    v
         +----- kernel tun0 ------+    <-- single VpnService TUN
         |  routes: union of all  |        addresses: union of all
         |  joiners' AllowedIPs   |        joiners' [Interface]
         +-----------+------------+        Address lines
                     |
                     v
         +---- gvisor netstack ----+    <-- routes by dst IP across
         |   NIC0 = kernel-TUN     |        N+1 NICs
         |   NIC1 = wg-joiner #1   |
         |   NIC2 = wg-joiner #2   |
         |   …                     |
         |   NICk = wg-joiner #k   |
         +-+----+----+----+--------+
           |    |    |    |
           v    v    v    v
        wg-go wg-go wg-go wg-go      <-- N userspace instances,
        (#1)  (#2)  (#3)  (#k)           each with its own UDP
           \    |    |    /              outer-transport socket
            \   |    |   /
         +---- OS sockets ----+        <-- protect()'d so they
         |  one per joiner   |            bypass the VpnService TUN
         +--------+----------+
                  |
                  v
              wire
```

**Packet flow**:

- *Outbound* (app → remote network): app writes to `tun0`; our
  reader pumps bytes into gvisor's NIC0; gvisor's routing table
  picks the matching joiner's NIC by longest-prefix match on the
  destination; that joiner's wg-go encrypts and sends on its
  protected UDP socket.

- *Inbound* (remote network → app): joiner's UDP socket receives;
  wg-go decrypts; plaintext IP packet lands on that joiner's
  gvisor NIC; gvisor routes it to NIC0 (the kernel TUN); our
  writer pushes it to `tun0`; kernel delivers to the app.

### Reconfigure model — preserving TCP across tunnel set changes

`Builder.addRoute()` must be called *before* `establish()`, so any
change to the joiner set forces a `Builder.establish()` rebuild.
But the rebuild is much less disruptive than first feared:

- **Kernel TCP state survives** the swap if the surviving joiners'
  source addresses and routes are unchanged in the new union.
  Open sockets are 4-tuple-keyed in the kernel; they don't bind to
  TUN identity. Packets drop for the millisecond between old TUN
  release and new TUN ready; TCP retransmits cover it.
- **Our gvisor flow tables survive** unconditionally — gvisor is
  in-process state. We just close the old TUN fd and pass gvisor
  the new one; the NIC0 reader/writer rebinds.
- **Wireguard-go sessions survive** unconditionally — each wg-go
  owns its own UDP outer socket, has its own session state,
  doesn't see the kernel TUN at all.

So the per-action picture:

| Action | What dies | What lives |
|---|---|---|
| Add joiner | nothing (brief packet loss during swap) | every existing TCP through every existing joiner |
| Remove joiner | TCP through the removed joiner | TCP through every other joiner |
| Edit joiner AllowedIPs (shrink) | TCP whose dst is no longer covered | everything still in coverage |
| Edit joiner AllowedIPs (grow) | nothing | everything |
| MTU floor changes | nothing immediately (PMTUD recovers in-flight) | everything |

This matches the use case: user sets up "home + work + hotel
guest network" once and leaves it; the rare add/remove costs at
most the connections explicitly tied to the affected tunnel.

### UI implication

A small, non-blocking banner when the user is about to add or
remove a joiner — "Other VPN connections may briefly interrupt"
— is appropriate; a full confirm dialog is overkill given how
rare reconfigure is in the target use case.

### Go-side surface change

`wgbridge_native` today exports two open paths:

- `open(localAddr, mtu, listenPort)` — netstack mode (host).
- `openWithTunFd(fd, mtu)` — TUN-fd mode (joiner today).

Joiner-N replaces the second with a third:

- `openIntoSharedNetstack(handle, localAddr, mtu)` — opens a wg-go
  in netstack mode and attaches it as a *NIC* on a pre-existing
  shared gvisor netstack (created by us). Multiple joiners can
  attach to the same shared netstack; routes are programmed per
  AllowedIPs.

Plus one path to wire the kernel TUN as gvisor's "NIC0":

- `bindKernelTunToSharedNetstack(handle, tunFd, mtu)` — starts a
  read goroutine that pumps the TUN fd into NIC0 and a write
  callback that delivers gvisor egress back to the TUN.

Total estimate: ~200 LOC in `wgbridge_native/`, plus a
`JoinerStackBackend` class on the Kotlin side parallel to today's
`HostModeBackend`.

### Tasks (Joiner-N)

- **D4.J1** — `wgbridge_native`: shared-netstack handle +
  `openIntoSharedNetstack` Go API + JNI binding. Unit-tested in
  Go (no Android required).
- **D4.J2** — `wgbridge_native`: `bindKernelTunToSharedNetstack`
  + read/write pumps. Tested with a Linux `/dev/net/tun` fixture.
- **D4.J3** — Kotlin `JoinerStackBackend` parallel to
  `HostModeBackend`. Same slot-map / pause-resume discipline.
  Owns the shared netstack handle; spawns / tears down NICs as
  joiners come and go.
- **D4.J4** — `JoinerVpnService` rewrite: maintains the kernel TUN,
  rebuilds `Builder.establish()` on the *set* of active joiners.
  Debounce reconfigures (200ms) to coalesce rapid add/remove.
- **D4.J5** — TCP preservation instrumented test: bring up two
  joiners with overlap-free AllowedIPs; open a TCP socket through
  joiner-1 (sandbox is the remote); add a third joiner; verify the
  TCP socket survives. Run on emulator (v4 outer + dual-stack
  inner) and ARC.
- **D4.J6** — `TunnelOverlapGuard` updated: refuse joiner-vs-joiner
  AllowedIPs overlap (gvisor needs unambiguous longest-prefix
  match). Today the guard already exists for host-vs-active; just
  extend the active set.
- **D4.J7** — UI: non-blocking banner on add/remove of a joiner.
  "Other VPN connections may briefly interrupt."
- **D4.J8** — Real-device validation: phone connects to home +
  work simultaneously. Phone shares both via host-N (cascade
  comes after). User-driven.

Estimated total: ~10 commits, mostly mechanical once D4.J1–J3 are
in. The risky/novel commits are D4.J1 and D4.J2 (Go + JNI).

## Secondary architecture — Cascade-N (on top of Joiner-N)

Once joiner-N is in, cascade is a small egress routing toggle:

> Per host tunnel, optionally route the host's gvisor egress
> through a named joiner instead of the OS network.

Today `HostModeBackend.toRunnerConfig()` wires
`EgressSelector.socketFactory()` → JVM `Socket` (OS-routed). For
cascade, that factory becomes:

```
egressFactoryForHost(hostId):
  return socketFactory whose .createSocket(...) opens a TCP/UDP
  flow inside the shared joiner netstack on NIC(joinerId-for-host).
```

gvisor already supports this — it has a netstack-internal
`socket.NewEndpoint(...)` API used by anyone writing a flow into
gvisor from outside. The host's gvisor catchall would dial via
this instead of via `java.net.Socket`. The wg-go on the cascade
joiner sees an inner packet whose source is the joiner's interface
address; encrypts; sends.

### Tasks (Cascade-N)

- **D4.C1** — Per-host-tunnel "cascade upstream" setting
  (`TunnelStore`). Choices: `os` (default) or `joiner:<id>`.
- **D4.C2** — `JoinerStackEgressFactory` — a `SocketFactory` /
  UDP egress factory that opens flows inside the shared joiner
  netstack. Implementation re-uses gvisor's user-facing socket
  API.
- **D4.C3** — Routing-loop guard: refuse cascade when host
  subnet ⊆ joiner AllowedIPs (would loop back into the cascading
  host).
- **D4.C4** — UI: host detail screen shows "Egress via {joiner
  name}" + a warning when the named joiner is down.
- **D4.C5** — MTU floor: cascade adds inner WG overhead; host
  tunnel's `MTU` floor recomputed against `joiner.mtu − overhead`.
- **D4.C6** — Instrumented end-to-end: emulator hosts a host
  tunnel + a joiner tunnel; sandbox WG client connects to the
  host; host's egress cascades through the joiner; second sandbox
  WG client (on the joiner side) sees the traffic.
- **D4.C7** — Real-device validation: Pixel hosts + cascades
  through a Chromebook joiner upstream; sandbox is the joining
  peer. User-driven.

Estimated total: ~5 commits, mostly Kotlin wiring once D4.J3 is
in. The Go side doesn't change for cascade.

## Risk register

| Risk | Severity | Mitigation |
|---|---|---|
| Reconfigure on add/remove drops TCP across surviving joiners | **Low** | Kernel TCP is 4-tuple-keyed; survives the swap as long as source addrs + routes match (see analysis above). Validated by **D4.J5**. |
| Shared gvisor NIC routing conflict on overlapping AllowedIPs | Medium | `TunnelOverlapGuard` already refuses overlap; **D4.J6** extends it to joiner-vs-joiner. |
| `Builder.establish()` returns null (user revoked VPN consent) | Medium | Surface as a per-tunnel error; pause all joiners until consent restored. Already handled for the single-joiner path. |
| Brief packet loss during TUN swap noticed by latency-sensitive apps | Low | TCP retransmits; UDP loses ≤ 1 datagram. Documented in UI banner. |
| MTU floor reduction on add invalidates in-flight large TCP packets | Low | PMTUD handles it within RTT; no app intervention needed. |
| N wireguard-go instances overload the Go runtime | Low | Host-N already runs N concurrent instances cleanly. Same pattern. |
| `bindKernelTunToSharedNetstack` read goroutine blocks under load | Medium | Use a buffered channel; cap to MTU × ringsize; drop oldest on overflow with logging. Standard gvisor pattern. |
| Cascade routing loop (host's gvisor egresses via a joiner whose AllowedIPs covers the host's subnet) | High → mitigated | **D4.C3** static check refuses the config. |
| Cascade joiner goes down mid-flow | Medium | Host tunnel's catchall gets `EHOSTUNREACH` from the joiner stack; surface in host detail UI. |
| Per-applicationId VPN consent (ChromeOS ARC) | Low | Document; no fix needed — already the existing constraint. |

## Open questions

1. **Joiner-N first?** Yes; joiner-N is the bigger architectural lift.
   Cascade-N becomes ~5 commits of Kotlin glue once joiner-N is in.
2. **Joiner-side "cascade-available" opt-in?** Plausible default:
   any joiner whose AllowedIPs is `0.0.0.0/0` is offered as a
   cascade upstream; otherwise opt-in via a per-tunnel toggle.
3. **Per-flow vs per-tunnel cascade routing?** Per-tunnel for v1.
   Per-flow (split-tunnel routing inside a host) is a v2 feature
   if anyone asks for it.
4. **Reconfigure debounce window?** 200ms feels right (user
   tapping "Add" then "Add" rapidly should coalesce). Confirm
   on the first real-device test.

## Prototypes I'd run before any production code

1. **`bindKernelTunToSharedNetstack` spike** — open a kernel TUN
   via `VpnService.Builder` in an instrumented test, hand the fd
   to a stub Go function that just reads packets and logs
   src/dst. Confirms the read pump works on real Android (vs the
   Linux fixture). 1 commit.
2. **Two-NIC gvisor netstack** — Go-side test (no Android): create
   a gvisor stack with two NICs, program a route, push an IP
   packet into NIC0, assert it lands on NIC1. Confirms gvisor
   API surface matches our needs. 1 commit.
3. **Kernel-TCP-survives-rebuild spike** — instrumented test that
   does `Builder.establish()` twice with identical addresses +
   routes, verifies an app socket (opened between the two
   `establish` calls) keeps working. Confirms the TCP-preservation
   thesis empirically on the emulator + ARC. 1 commit.

Three prototypes, each independent, each retiring a separate
assumption. If any one fails we pause and re-plan before committing
to the rest. **D4.J1** doesn't start until the three pass.
