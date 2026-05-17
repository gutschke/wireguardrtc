# CASCADE-2 — Cross-stack forwarding plan

**Status:** Draft v4 (2026-05-17).  Option B (forwarding bridge)
with §6 (route ordering) and §8 (black-hole) rewritten to use
mechanisms that actually work against gvisor's API after the v3
review.  Not yet implemented.  Task #379.

## Problem

When a user runs both a host-mode wgrtc tunnel and a joiner-mode
wgrtc tunnel concurrently in the same Android app, traffic decrypted
on the host-mode side cannot be re-encrypted and forwarded out the
joiner-mode tunnel.  The two tunnels run on *separate* gvisor netstack
instances with no shared routing path.

CASCADE-1 (landed) relaxed the UI overlap guard.  CASCADE-2 makes
the traffic actually flow.


## Current architecture (verified)

Two distinct gvisor netstack instances with incompatible design
choices that prevent simple unification:

- **Host-mode** (`api.go:wgbridgeNew`): uses
  `golang.zx2c4.com/wireguard/tun/netstack.CreateNetTUN`, which
  internally builds a `stack.Stack` with `HandleLocal: true`.
  Exposes a `*netstack.Net` whose `DialTCP` / `ListenTCP` /
  `ListenUDP` / `Ping*` surface relies on the transport layer
  delivering locally-destined packets to registered endpoints.
- **Joiner-N** (`joiner_n_stack.go:newSharedStack`): explicit
  `stack.New(...)` with **`HandleLocal: false`** (line 164).
  The pump model treats every NIC as a transit interface;
  locally-destined packets surface on a channel.Endpoint, not
  at a transport endpoint.

Switching either stack's `HandleLocal` setting requires rebuilding
that side's transport-layer code path — ~1-2 weeks of work alone.
This is why Option A (unified stack) costs 5-7 weeks honestly.


## Selected approach: Option B (forwarding bridge)

Keep both stacks with their existing `HandleLocal` settings.  Add a
**cascade ferry**: a paired channel.Endpoint with one endpoint
attached as a NIC on each stack, plus two drain-loop goroutines that
move packets between them.  Routes on each side direct cascade
traffic to the ferry NIC; the partner stack delivers via
`InjectInbound`.

Estimate: **3-4 weeks** single-developer, accounting for the
correctness-bug fixes in §6, §7, §8 below.

Comparison to Option A (5-7 weeks): Option B trades two architectural
fragmentations (two stacks instead of one) for avoiding the
HandleLocal collision and reusing existing drain-loop patterns.

**Trigger to reconsider Option A:** if any one of §6 / §7 / §8 below
exceeds 4 days of implementation effort, escalate this back to a
design-review decision.  The breakeven point is roughly halfway to
Option A's cost.


## Detailed design

### 1. Ferry primitives

```go
// CascadeFerry plumbs IP packets between a host-mode stack
// (HandleLocal=true) and the joiner-N shared stack
// (HandleLocal=false) via a paired channel.Endpoint with two
// drain-loop goroutines.
type CascadeFerry struct {
    hostStack    *gvstack.Stack
    joinerStack  *gvstack.Stack
    hostNicID    tcpip.NICID
    joinerNicID  tcpip.NICID
    hostEp       *gvchannel.Endpoint
    joinerEp     *gvchannel.Endpoint
    ctx          context.Context
    cancel       context.CancelFunc
    done         chan struct{}
}

func newCascadeFerry(hostStack, joinerStack *gvstack.Stack, mtu uint32) (*CascadeFerry, error)

func (f *CascadeFerry) AddHostRoute(prefix netip.Prefix) error
func (f *CascadeFerry) AddJoinerRoute(prefix netip.Prefix) error
func (f *CascadeFerry) RemoveHostRoute(prefix netip.Prefix) error
func (f *CascadeFerry) RemoveJoinerRoute(prefix netip.Prefix) error
func (f *CascadeFerry) Stop()
```

### 2. MTU at ferry endpoints

The ferry's channel.Endpoint MTU is set to **max(hostStack MTU,
joinerStack MTU)** at construction so the ferry never imposes its
own fragmentation.  Each side's existing wireguard-go device
applies its own MTU policy independently; the ferry is a pure
userspace pipe.

### 3. Strong-host markers — joiner-stack side only

The ferry NIC on the joiner-N stack binds v4 + v6 strong-host
markers via `bindStrongHostMarkers` (reused from joiner_n_stack.go).
The ferry NIC on the host-mode stack does **not** bind markers —
host-mode runs `HandleLocal: true`, where strong-host isn't
enforced.  Binding markers there would be a no-op and confuse the
host stack's address table.

### 4. Drain-loop goroutines — `InjectInbound`, not `WritePackets`

**Correction of v2 plan:** the v2 pseudocode incorrectly used
`WritePackets` on the destination endpoint.  `WritePackets`
*queues for `Read`* (outbound from a stack's perspective).  We
want to *deliver inbound* to the destination stack — that's
`InjectInbound`.  Same primitive pattern joiner_n_pump.go uses
on line 91.

```go
// host-stack → joiner-stack direction
go func() {
    defer close(f.hostToJoinerDone)
    for {
        pkt := f.hostEp.ReadContext(f.ctx)
        if pkt == nil { return }
        proto := protoFromIPVersion(pkt)
        view := pkt.ToView()
        pkt.DecRef()
        clone := gvstack.NewPacketBuffer(gvstack.PacketBufferOptions{
            Payload: buffer.MakeWithData(view.AsSlice()),
        })
        view.Release()
        f.joinerEp.InjectInbound(proto, clone)
        clone.DecRef()
    }
}()
// joiner-stack → host-stack direction: symmetric
```

Note: `ReadContext(ctx)` (not non-blocking `Read()` + `select`) is
the right primitive.  This matches joiner_n_pump.go's pattern and
avoids CPU-spinning when the queue is idle.

### 5. Lifecycle: registry

```go
type CascadeFerryRegistry struct {
    mu          sync.Mutex
    joinerStack *gvstack.Stack       // nil until joiner-N up
    hostStacks  map[int32]*hostStackState  // by bridge handle
    ferries     map[int32]*CascadeFerry     // one per host bridge
}

type hostStackState struct {
    stack          *gvstack.Stack
    peerSubnets    []netip.Prefix  // host-mode's claimed subnets
    dropNicID      tcpip.NICID     // synthetic drop-NIC for §8
    dropEp         *gvchannel.Endpoint
}
```

Events:
- **RegisterJoinerStack(s, allowedIPs)** — record stack +
  union of joiner peers' AllowedIPs; if any host bridges
  are registered, create ferries for each.
- **UnregisterJoinerStack()** — stop all ferries, swap host-side
  cascade routes to drop-NIC (see §8).
- **RegisterHostBridge(handle, s, peerSubnets)** — record; if
  joiner stack is up, create a ferry and install routes:
  - on host stack: `AddRoute(prefix → ferry.hostNicID)` for each
    prefix in the union of joiner peers' AllowedIPs.
  - on joiner stack: `AddRoute(peerSubnet → ferry.joinerNicID)`
    for each of this host bridge's `peerSubnets`.
- **UnregisterHostBridge(handle)** — stop that ferry, remove
  routes on both stacks.
- **OnJoinerAllowedIPsChanged(allowedIPs)** — joiner-N AllowedIPs
  may have changed at reconfigure time; recompute host-stack
  cascade routes (add new, remove gone).  See §8 for the
  full-rebuild case which goes through `onBeforeRebuild` instead.

Programmer-error invariants (asserted in registry, panic on
violation):
- Multiple host bridges claiming identical `peerSubnets`
  prefix → CASCADE-1's `TunnelOverlapGuard` refuses this at
  Connect time.  Registry panics if it ever sees it (defence
  in depth).
- Identical-prefix collision between any host bridge's
  `peerSubnet` and any joiner-N AllowedIP → also CASCADE-1
  refused.  Registry panics if it ever sees it.

**Prefix derivation:** the cascade routes the registry
installs are derived as:
- Host-stack-side routes: union of joiner-N's `allowedIPs`
  (passed to `RegisterJoinerStack` / `OnJoinerAllowedIPsChanged`).
- Joiner-stack-side routes: union of all host bridges'
  `peerSubnets`.

Both unions are recomputed on each event.

### 6. **Host-stack route management — explicit ordering for equal-prefix collisions**

`host_forwarder.go` currently uses `stk.SetRouteTable(routes)`
(line 247), which **replaces** the host stack's entire route
table.  Any cascade routes installed before would be wiped.

**More subtle problem**: gvisor's `addRouteLocked` (stack.go:766)
inserts a new route *after* any equal-prefix route already in
the table.  `FindRoute` (stack.go:1516) iterates the table in
order and the first matching enabled NIC wins.  So among
equal-prefix routes, **first-inserted wins**.

For non-default cascade prefixes (e.g. `10.50.0.0/24`) this
doesn't matter — the forwarder's catchall is `0.0.0.0/0` and
LPM picks the more-specific `/24` regardless of insertion
order.

**But the user's actual scenario hits the equal-prefix case:**
the joiner-N peer claims `AllowedIPs = 0.0.0.0/0, ::/0` (full
tunnel).  Cascade installs `0.0.0.0/0 → ferryNIC` on the host
stack.  The forwarder already has `0.0.0.0/0 → NIC2` (its
catchall).  With install-order undefined, the cascade route can
silently lose the LPM tie-break and traffic leaks via the
forwarder's NIC2 → OS sockets.

**Strategy: refactor + `ReplaceRoute`-like sequence for
defaults.**

1. Replace `SetRouteTable(allRoutes)` in `host_forwarder.go`
   with explicit `AddRoute(route)` calls.  Track the routes
   the forwarder owns in a slice on `hostForwarderState` for
   later removal via `RemoveRoutes(predicate)` — gvisor's
   actual API is `RemoveRoutes(match func(tcpip.Route) bool)
   int` (stack.go:780); there is no singular `RemoveRoute`.
   The predicate matches the forwarder's tracked routes by
   `(Destination, NIC)` tuple.

2. **Cascade route install for default-route case is a
   3-step transaction:**
   ```go
   // Before: forwarder catchall exists at 0.0.0.0/0 → NIC2.
   // We want: cascade route 0.0.0.0/0 → ferryNIC to win LPM
   // tie-breaks against the forwarder catchall.
   //
   // Step 1: Remove forwarder catchall (it'll be reinstalled
   //         after the cascade route).
   stk.RemoveRoutes(func(r tcpip.Route) bool {
       return r.Destination.Equal(zeroV4Subnet) &&
              r.NIC == forwarder.catchallNicID
   })
   // Step 2: Install cascade default route FIRST.
   stk.AddRoute(tcpip.Route{
       Destination: zeroV4Subnet,
       NIC:         ferry.hostNicID,
   })
   // Step 3: Re-install forwarder catchall AFTER cascade,
   //         so it loses LPM tie-breaks but remains the
   //         fallback when no cascade is installed.
   stk.AddRoute(tcpip.Route{
       Destination: zeroV4Subnet,
       NIC:         forwarder.catchallNicID,
   })
   ```
   This sequence runs under the registry's mutex AND uses
   gvisor's stack.mu transparently (the AddRoute / RemoveRoutes
   calls each take it).  Net effect: cascade is the FIRST
   match in the route table for `0.0.0.0/0`, forwarder is
   second.

3. Non-default cascade prefixes (anything more specific than
   `0.0.0.0/0` / `::/0`) skip the transaction and use plain
   `AddRoute` — LPM resolves them above the forwarder
   catchall regardless of insertion order.

4. **Cascade route removal** is the reverse: if cascade had to
   evict a forwarder catchall, restore the forwarder catchall
   after `RemoveRoutes(cascade)`.

Implementation: ~50-100 lines of changes to `host_forwarder.go`
+ a `RouteOwnership` helper struct that tracks who owns which
routes.  Test in Phase 3 must include an explicit equal-prefix
ordering assertion: install forwarder catchall, install cascade
default via the 3-step transaction, send a packet, assert it
took the cascade path.

`RemoveRoutes` predicate matches by full route equality (the
`tcpip.Route` is comparable as a struct including
Destination + NIC + Gateway + SourceHint).  The forwarder
keeps its routes as plain Go structs for later predicate
matching.

### 7. **Temp-local address shadowing — registry consultation**

`host_forwarder.go`'s `redirectViaTempAddress` accumulates `/32`
and `/128` temp-locals on the host NIC for the through-host NAT
trick.  With `HandleLocal: true`, gvisor delivers any packet
whose dst matches a temp-local address to the local stack —
**bypassing the route table entirely**.  So a cascade prefix
`10.50.0.0/24` is shadowed by any temp-local at `10.50.0.5/32`
that was registered before the cascade prefix existed.

**Refactor:** introduce a `CascadeFerryRegistry.HasCascadePrefix(dst
netip.Addr) bool` method.  Before
`redirectViaTempAddress` registers a temp-local on the host
NIC, it calls the registry.  If `dst` falls inside any active
cascade prefix, the temp-local is **not** added; instead the
forwarder returns early so gvisor falls through to LPM route
resolution → ferry NIC → joiner stack.

Symmetric handling for the reverse case: when a cascade prefix
is added to the registry, audit existing temp-locals on host
NICs and remove any that now fall under the prefix.

Implementation: ~50 lines + tests.  Adds an explicit
forwarder ↔ registry dependency, which is fine — they're already
both wired through `bridgeState`.

### 8. **Joiner-N rebuild handling — synthetic drop-NIC, ferry NIC stays alive**

`JoinerNController.rebuildLocked` creates a fresh
`*sharedStackState` and `*gvstack.Stack` pointer when joiner-N
reconfigures.  The old stack is torn down; the new stack is
built.  The gap window spans several seconds.

Without handling, during the gap:
- The registry's `joinerStack` pointer is stale.
- The host stack's cascade routes still point at the ferry's
  host-side NIC, but the ferry's drain-loop goroutine is
  trying to call `InjectInbound` on a now-dead joiner endpoint.
- Host-mode-side packets matching cascade prefixes leak through
  the forwarder's catchall NIC → OS sockets — privacy bug.

**v3 attempted `stk.AddRoute(tcpip.Route{NIC: 0})` as a
black-hole.  This does not work.**  gvisor rejects NIC 0 at
`CreateNICWithOptions` (stack.go:908) and `FindRoute` skips
routes whose NIC isn't present in `s.nics` (stack.go:1521-1524).
Routes to NIC=0 are inert, not drop.  Worse, `RemoveNIC`
(stack.go:1019-1042) sweeps all routes pointing at the
removed NIC — so if the registry tries to tear down the
ferry NIC during the gap, the cascade routes vanish entirely
and traffic falls through to the forwarder's catchall.

**Correct design (v4): synthetic drop-NIC + ferry-NIC-stays-alive.**

At ferry construction time, the registry also creates a
**permanent synthetic drop-NIC** on each host stack — a
`gvchannel.New(0, mtu, "")` (capacity 0 → all packets dropped
immediately) attached as a NIC, with a no-op drain goroutine
that `Drain()`s into nothing.  The drop-NIC has no routes
pointing at it initially.

Gap-handling sequence:

1. **JoinerNController emits `onBeforeRebuild` synchronously**
   (registered via a new pre-teardown hook in the controller).
2. Registry, in the callback:
   a. For each active ferry, do a **route-swap transaction**
      under the registry's mutex on the host stack:
      ```go
      // Replace cascade routes with drop-NIC routes.
      // The cascade routes' destinations stay the same; only
      // the NIC changes.  Use RemoveRoutes(predicate) + AddRoute.
      stk.RemoveRoutes(func(r tcpip.Route) bool {
          return r.NIC == ferry.hostNicID
      })
      for _, p := range cascadePrefixes {
          stk.AddRoute(tcpip.Route{Destination: p, NIC: dropNicID})
      }
      // If the forwarder's catchall was at the same prefix as
      // a cascade default route, it remains in the table —
      // unchanged from the original install order.  But our
      // drop-NIC route went in first under §6's 3-step
      // transaction, so drop-NIC wins LPM tie-break.
      ```
   b. Cancel the ferry's drain-loop contexts (`f.cancel()`).
   c. **Block until both drain-loop goroutines have exited.**
      Use `<-f.hostToJoinerDone; <-f.joinerToHostDone`.
      This guarantees no goroutine still holds the
      about-to-be-invalid joiner-stack pointer.
   d. **Do NOT remove the host-side ferry NIC.**  It stays
      alive across the gap so its routes can be put back
      cleanly.  The joiner-side endpoint will be detached
      from the dying joiner stack by joiner stack teardown;
      the host-side endpoint persists.
3. Callback returns.  JoinerNController proceeds with
   `backend.closeAll()` → joiner stack is destroyed.
4. JoinerNController completes the rebuild → new joiner
   stack pointer.
5. JoinerNController emits `onAfterRebuild(newStack)`.
6. Registry:
   a. Creates a fresh joiner-side endpoint on the new joiner
      stack via `attachNic`, install strong-host markers.
   b. Updates each ferry's `joinerStack`, `joinerNicID`,
      `joinerEp` to the new values.  The host-side state
      stays the same.
   c. Restarts the drain-loop goroutines.
   d. Route-swap transaction on the host stack:
      `RemoveRoutes(NIC == dropNicID) + AddRoute(NIC ==
      ferry.hostNicID)` for each cascade prefix.

During the gap:
- Host-mode side: packets matching cascade prefixes hit the
  drop-NIC's route → gvisor's `FindRoute` resolves the NIC
  → tries to forward via the NIC's link endpoint → packet
  goes to the cap-0 channel.queue.Write → silently dropped.
  **No leak.**
- Joiner-N side: stack is being rebuilt; no traffic flows
  there anyway.

Concretely, the gap-window behavior is **drop, not leak**.

Drop-NIC lifecycle: created at first ferry registration on a
host stack, never destroyed.  One drop-NIC per host stack.
Cost: one extra NIC + one idle goroutine per host bridge.

### 8.1 `Drain`-and-discard goroutine (drop-NIC drain loop)

```go
// drop-NIC drain: pull packets off the cap-0 channel.queue
// and DecRef them so PacketBuffer pool can reclaim.  Even
// with capacity 0, the gvisor IP layer still calls
// WritePackets which goes through queue.Write — and queue.Write
// at cap=0 enters the "queue full" path immediately and drops.
// But gvisor's WritePackets path still calls AddRef on the
// packet before queueing, so we DON'T need to drain — the
// AddRef + immediate-drop balances out the lifecycle.
// Goroutine isn't even needed.  Drop-NIC just IS a cap-0
// channel.Endpoint with no readers.
```

Actually, on review, the drain goroutine is not needed at
all.  Cap=0 channel.Endpoint with no `Read` simply drops
silently.  Simplifies the design.

### 9. JNI surface

```c
// New exports, namespaced under wgbridgeSharedStack* to match
// the existing wgbridgeSharedStackOpenJoiner / Close family.
int wgbridgeSharedStackCascadeStart(int joinerStackHandle, int hostBridgeHandle);
int wgbridgeSharedStackCascadeStop(int hostBridgeHandle);
int wgbridgeSharedStackCascadeAddHostRoute(int hostBridgeHandle, const char *prefix);
int wgbridgeSharedStackCascadeAddJoinerRoute(int hostBridgeHandle, const char *prefix);
int wgbridgeSharedStackCascadeRemoveHostRoute(int hostBridgeHandle, const char *prefix);
int wgbridgeSharedStackCascadeRemoveJoinerRoute(int hostBridgeHandle, const char *prefix);
```

### 10. Kotlin wiring

`CascadeWiring` (Kotlin singleton) observes:
- `JoinerStackBackend.activeStackState: StateFlow<StackState?>`
  (new — emits the current shared stack handle, null when down)
- `HostModeBackend.activeTunnelIds: StateFlow<Set<String>>`
- `JoinerStackBackend.allowedIpsByJoiner: StateFlow<Map<TunnelId, List<Prefix>>>`
  (new — emits the union of AllowedIPs across all active joiners)

On every state change, the wiring computes the desired set of
(host-bridge, joiner-stack) pairs and the routes each should
hold, then issues JNI calls to bring the registry to that state.
Idempotent: the registry tracks current state and applies only
diffs.

`SettingsStore.cascadeEnabled` (new flag, default OFF) gates
the wiring.  When off, `CascadeWiring` does nothing.

### 11. Reconfigure event plumbing

JoinerNController gets two new synchronous hooks:
- `onBeforeRebuild()` — fires **before** `backend.closeAll()`.
  Callback runs synchronously within the controller's
  `mu.withLock` critical section.  Used by CascadeWiring →
  registry to swap cascade routes to drop-NIC AND wait for
  ferry drain-loop goroutines to exit before returning.
  The callback BLOCKS until ferry teardown is complete; the
  controller does not proceed with `closeAll` until the
  callback returns.
- `onAfterRebuild(newStack)` — fires after rebuild completes
  with the new shared-stack pointer.  Registry creates new
  joiner-side endpoints + restores cascade routes.

Both hooks return errors; if `onBeforeRebuild` fails (e.g.
drain-loop won't exit), the controller logs and proceeds
anyway with a forced teardown — leaking is preferable to
hanging.  Actually, on second thought, no: hang the
reconfigure rather than leak.  The user's perceived bug is
"my joiner-N reconfigure hangs for 30s" vs.
"my data leaked out the wrong interface."  Hang wins.

### 11.1 Settings UI

Cascade is gated by `SettingsStore.cascadeEnabled` (new
boolean flag, default OFF).  UI toggle lives in
`SettingsScreen.kt` as a sibling section to
`JoinerModeSection` (the existing joiner-N opt-in toggle that
landed in v0.2.10).  Same `Row { Column { Text + Text } +
Switch }` template.


## Test strategy (TDD)

### Phase 1: Ferry primitives (pure Go, ~2-3 days)

Tests written **first**:
- `TestCascadeFerryHostToJoinerDirection` — packet injected on
  host stack's NIC matching cascade route emerges on joiner
  stack as if from the wire.  Uses `InjectInbound`-receives-on-
  destination semantics.
- `TestCascadeFerryJoinerToHostDirection` — symmetric.
- `TestCascadeFerryV6Direction` — v6 packets across both
  directions.
- `TestCascadeFerryStopReleasesGoroutines` — `runtime.NumGoroutine`
  delta-check after `Stop()`.
- `TestCascadeFerryStopDrainsInFlight` — inject N packets in
  rapid sequence, call `Stop()` immediately, verify
  no panic / no leak.  Stop must wait for in-flight
  ferry passes to complete or explicitly drop them with a
  counter visible to the test.
- `TestCascadeFerryRouteAddRemove` — add and remove leaves the
  route table consistent.
- `TestCascadeFerryStrongHostMarkers` — joiner-side ferry NIC
  has v4 + v6 markers; host-side does NOT (since HandleLocal:true).

Implementation: `cascade_ferry.go`, ~200 lines.

### Phase 2: Registry orchestration (pure Go, ~2 days)

- `TestRegistryStartOnBothPresent` — register joiner-stack alone
  → no ferries.  Add host-bridge → ferries appear.
- `TestRegistryStopOnEitherGone` — both registered → ferries
  alive.  Unregister joiner → ferries stop AND black-hole
  routes installed.
- `TestRegistryMultipleHostBridges` — register joiner + 2 host
  bridges → 2 ferries.
- `TestRegistryRouteSyncOnAllowedIPsChange` — host bridge
  registered, joiner stack registered, AllowedIPs event fires
  → routes appear on both directions of the ferry.
- `TestRegistryRebuildBlackholeDuringGap` — joiner-stack
  teardown event → black-hole routes installed BEFORE ferries
  stop; joiner-stack rebuilt event → black-holes replaced with
  fresh ferry routes.
- `TestRegistryHasCascadePrefix` — the lookup API used by
  host_forwarder for temp-local-shadowing avoidance.

Implementation: `cascade_ferry_registry.go`, ~150 lines.

### Phase 3: host_forwarder refactor (~2 days)

- `TestHostForwarderUsesAddRouteNotSetRouteTable` — source-lint:
  no `SetRouteTable` calls in host_forwarder.go production code.
- `TestHostForwarderPreservesPreexistingRoutes` — install some
  fake routes via `AddRoute`, call `wgbridgeInstallHostForwarder`,
  assert the fake routes are still there.
- `TestHostForwarderSkipsTempLocalForCascadePrefix` — register
  a cascade prefix in the registry, have the forwarder process
  a packet whose dst falls under that prefix, assert no
  temp-local was registered.
- `TestRegistryUnregistersTempLocalsWhenCascadePrefixAdded` —
  pre-existing temp-locals get cleaned up when a cascade prefix
  is added.

Refactor: ~50-100 lines of changes to `host_forwarder.go`,
swap `SetRouteTable` → tracked `AddRoute`/`RemoveRoute`,
introduce the registry-consultation in `redirectViaTempAddress`.

### Phase 4: gvisor-only end-to-end (pure Go, ~2 days)

Per the v2-review's NICE-TO-FIX item: scope Phase 4 to **gvisor
only**, no real wireguard-go on the test rig.  The cascade data
path is a routing question; wg-go integration is Phase 5's job.

- `TestCascadeFlowGvisorOnly` — set up host stack + joiner stack
  + ferry; use `gonet.DialUDP` on host stack to "send" a packet
  destined for a joiner-side AllowedIPs prefix; use
  `gonet.ListenUDP` on joiner stack to confirm packet arrives.
- `TestCascadeReverseFlowGvisorOnly` — joiner peer → host-bridge
  subnet direction.  Verifies that gvisor's existing host-stack
  `peerSubnet → NIC1` route (installed by host_forwarder) wins
  LPM over any cascade catchall on the joiner side, so a packet
  arriving on the joiner-stack-side ferry NIC with dst in a
  host's peer subnet flows to host-NIC1 (wireguard-go encrypts
  to external peer).  Make the LPM-win-by-specificity
  assertion explicit.

Saves 2-3 days of test-infrastructure work for real wg-go
handshakes that would replicate what Phase 5 catches anyway.

### Phase 5: Real-device validation (~3 days)

Topology on the user's test rigs:
- **Wireguard server at 10.10.0.122** acts as the external
  joiner-N target.
- **Emulator** (10.10.0.118) runs wgrtc with host-mode tunnel +
  joiner-N tunnel both up.  Joiner-N peers to 10.10.0.122.
  Host-mode listens on a public-ish port.
- **Unshare sandbox** runs a regular `wg` client that connects
  to the emulator's host-mode tunnel.

Assertions:
- A v4 ping from the sandbox client to a 10.10.0.122-reachable
  destination traverses sandbox → emulator host-mode → emulator
  joiner-N → 10.10.0.122-LAN → destination.
- A v6 ping similarly.
- Counters on 10.10.0.122's `wg show` increment for the joiner-N
  peer; counters on the emulator-side host-mode `wg show`
  increment for the sandbox peer.
- During an AllowedIPs reconfigure on the emulator's joiner-N,
  traffic is **dropped** (not leaked) for the duration of the
  rebuild window.  Verified via tcpdump on the cellular interface
  to ensure no packets leak.

### Phase 6: Regression pins (~0.5 day)

- Source-lint: `host_forwarder.go` does not call `SetRouteTable`
  in production code.
- Source-lint: `cascade_ferry.go` uses `InjectInbound` on the
  destination endpoint in drain loops (not `WritePackets`).
- CI reflection-check: `extractStack` and
  `extractChannelEndpoint` continue to locate their fields on
  the currently-vendored wireguard-go.  Fails loudly on bump.

### Phase 7: Source-lint for `wgbridgeNew` (~0.1 day)

`wgbridgeNew` continues to use the upstream `netstack.CreateNetTUN`
— pinned by source-lint so a future refactor doesn't accidentally
swap it for our own NIC machinery without doing the full Option A
work.


## Risks and mitigations

1. **Two memory copies per packet** — verified small at our scale;
   profile if cascade throughput becomes a real workload.
2. **`tnet.Stack()` upstream stability** — already used by host
   forwarder, Phase 6 reflection-check in CI guards against
   accidental drift on wireguard-go bumps.
3. **§8 black-hole gap drops legit traffic during reconfigure** —
   trade-off: privacy > availability for the few seconds of a
   reconfigure.  Documented user-visible behaviour.
4. **CASCADE-1 subset-of-superset** — out of scope.  The user's
   workaround (carve subnets out by hand) still applies for
   intentional overrides.

## Open items resolved

| Question | Decision |
|---|---|
| Black-hole vs leak during reconfigure gap | Black-hole (§8) |
| Ferry MTU | max(host, joiner) (§2) |
| Strong-host markers on host-side ferry NIC | Skip (§3) |
| Effort estimate | 3-4 weeks honest; 4 days breakeven trigger to Option A |
| Phase 4 scope | gvisor-only (no real wg-go); wg-go integration in Phase 5 |
| JNI naming | wgbridgeSharedStackCascade* prefix |
| Feature flag default | OFF in first release; flip after field validation |

## Truly open

None.  Plan is committable absent fresh review findings.
