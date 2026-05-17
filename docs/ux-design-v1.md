# wgrtc UX Design v1 — "Connections, not Configs"

Status: draft for adversarial review
Audience: maintainers + one critic
Scope: phone-first Android UI. ARC-on-Chromebook is a secondary target.

---

## 0. One-paragraph thesis

The current app exposes WireGuard's mental model: a tunnel is a config object, you flip
it on, you flip it off, and a hidden "cascade" toggle in Settings might or might not
make two of them talk to each other. That model is wrong for everyone except the people
who built it. Real users have **destinations** they want to reach and **services**
they want to publish. Everything else — host vs. joiner, VpnService vs. userspace
socket, cascade route insertion — is plumbing. This redesign promotes the plumbing's
*effects* to first-class objects (a **Connection** is a directed reachability claim;
a **Bridge** is what the app composes automatically when two connections cover the
same address space) and demotes the plumbing itself to a diagnostic surface that only
appears when something is wrong.

The load-bearing change is **a single authoritative state machine per tunnel**,
driven by every observable signal (VpnService onRevoke, last-handshake-time, network
change, peer set delta, JNI device-bring-up callback) — and the ViewModel subscribes
to *that*, not to whichever knob the user last touched. Every UX pain point in the
brief reduces to "the ViewModel disagrees with reality." Fix the disagreement at
the source, and the symptoms evaporate.

---

## 1. Tunnel state model — the load-bearing part

Every tunnel — host or joiner, single or part of a relay — owns one instance of the
following state machine. The ViewModel observes a `StateFlow<TunnelState>` and the
UI never inspects backend booleans directly.

### 1.1 States

```
Disabled               user has the tunnel saved but has not asked for it to run
Arming                 user tapped Connect; we are gathering preconditions
                       (consent grant, port bind, network probe, key load)
Connecting             preconditions satisfied; handshake in flight
Connected              last handshake < HANDSHAKE_STALE_SEC ago AND data path verified
Idle                   Connected-by-config but no recent handshake (joiner with
                       no traffic and no keepalive; not a fault)
Degraded               handshake stale but socket alive; probably roaming / network
                       transition; auto-recovery in progress
Paused (system)        Android revoked VpnService, OR a higher-priority VPN took over,
                       OR Doze killed the foreground service. Distinct from user pause.
Paused (user)          user tapped the same row twice; sticky across reboots
Failed (recoverable)   handshake never landed, port collision, DNS resolution failed,
                       endpoint unreachable; the next network event re-arms
Failed (permanent)     consent denied, key material corrupt, peer's public key
                       rejected by remote, ChromeOS routing-loop precondition violated;
                       requires user action and we say so
```

The eight-state alphabet is deliberate. Five states for normal operation, two pause
flavors that **must** be distinguishable (because Paused-system means we should show
"Reconnect when system allows", Paused-user means we should show "You paused this"),
and two failure flavors that map to two very different remediations.

### 1.2 Signals and transitions

| Signal | Source | Effect |
|---|---|---|
| `vpnService.onRevoke()` | VpnService callback we will start overriding | All joiners → Paused (system). ViewModel observes a `MutableSharedFlow<RevokeEvent>` that the service emits before `stopSelf()`. |
| `nativeBridge.deviceReady()` | JNI up-call after wireguard-go bring-up | Arming → Connecting |
| `lastHandshakeTime` poll (5 s cadence; already exists) | UAPI `get` | Connecting → Connected on first non-zero handshake; Connected → Idle after `HANDSHAKE_STALE_SEC = 180`; Idle → Degraded on user-initiated traffic that fails. |
| `ConnectivityManager.NetworkCallback.onLost` / `onAvailable` | system | Connected → Degraded → Connecting (auto re-arm) |
| Peer-set delta from offer-listener | WSS endpoint roam | does not change state; just updates endpoint, may unblock Degraded |
| Port bind EADDRINUSE | host mode UDP bind | Arming → Failed (recoverable) with **specific** message naming the conflicting socket if `lsof`-equivalent JNI lookup succeeds |
| Routing-loop probe failure | new: see §6.2 | Arming → Failed (permanent) with the loop diagnosis |
| Same-uid traffic dropped | gvisor netstack stat (we already count it) | informational only — never a state change, but surfaced in detail view |

### 1.3 Two invariants

**Invariant 1: the ViewModel is downstream of the service, never upstream of it.**
Today, `_activeJoinerNTunnelIds` is a `MutableStateFlow` mutated by the UI when the
user taps Connect, and *also* read by the UI to draw the row. When the system revokes
consent, the service dies but the flow never gets updated. We invert this: the
service owns a `TunnelStateRegistry` (process-wide, in-memory, rebuilt from UAPI on
service start), and the ViewModel **only reads** from it. The Connect button posts a
command to the service; the service mutates the registry; the registry emits; the UI
redraws. There is no UI-owned "is this tunnel on" boolean anywhere.

**Invariant 2: state is derived, not stored.** `Connected` is not a flag — it's the
result of `lastHandshakeTime > now - 180s AND service.deviceAlive(id) AND
!consentRevoked(id)`. If any of those flips, the derived state flips on the next
emission. This kills the phantom-active bug by construction: the moment `onRevoke`
fires, `consentRevoked` becomes true, the derived state becomes `Paused (system)`,
the UI re-renders.

---

## 2. Cascade: no toggle, ever

Drop the global Settings toggle. Cascade is not a feature; it's an emergent property
of two Connections covering the same address space.

### 2.1 The rule

A cascade route from host tunnel H to joiner tunnel J is **installed automatically**
when all of:

1. H is in state `Connected` and J is in state `Connected` (not Idle, not Degraded).
2. H has AllowedIPs P_H and J has AllowedIPs P_J such that some peer on H has
   AllowedIPs that *exclude* a subnet in P_J — i.e., the H-side peer wants to reach
   addresses that only J can deliver.
3. The user has not explicitly marked H or J as `relay: never` in tunnel detail.

The route is **torn down** the moment J leaves `Connected`. This is a JNI hop per
event (~1-5 ms per the brief), which is fine: cascade events are at the cadence of
network changes, not packets.

### 2.2 Why not a toggle

A toggle requires the user to know:
- what cascade is,
- that they want it,
- and to revisit Settings whenever they add a new tunnel.

The brief's pain point #1 is real. Three of those costs are paid every install; the
benefit is zero in the simple-joiner case (A) which is the majority. The toggle is
asymmetric in the wrong direction.

### 2.3 Counter-argument I want the critic to push on

There is one case where automatic cascade is wrong: the user has a "personal" joiner
(e.g., their work VPN, full-tunnel `0.0.0.0/0`) and a "guest" host tunnel for their
sibling visiting with a laptop. They *do not* want their sibling's traffic egressing
through their work VPN. The address-space rule fires here because the joiner covers
everything. The mitigation is the relay-per-tunnel opt-out (`relay: never`), but
relying on the user to discover it is exactly the failure mode of a global toggle.

Proposed resolution: when a newly-Connected joiner first becomes eligible to relay
for an already-Connected host, show a **one-shot, dismissable banner** on the host
tunnel's row: "Devices on *Home* can now reach *Work VPN*. [Allow] [Block]". The
banner stickies the choice in the relay policy of the host tunnel. Default is
**Block** for full-tunnel joiners (AllowedIPs covers a default route) and **Allow**
otherwise. This is the only nudge; everything else is implicit.

---

## 3. TunnelList: the row is a Connection

### 3.1 Reframing: kill "host" and "joiner" as user-facing words

Show **Connections**. A Connection has:
- a **name** (user-given or imported from config)
- a **direction badge** (small icon, not text):
  - arrow into a phone glyph = inbound (host)
  - arrow out of a phone glyph = outbound (joiner)
  - two arrows = bridge (host + cascade-active joiner)
- a **status pill** drawn from §1's state alphabet, color-coded:
  - green Connected, gray Idle, amber Degraded/Paused-system, blue Paused-user,
    red Failed-recoverable, dark red Failed-permanent, neutral Disabled
- a **right-side switch** that toggles between Disabled and (whatever the user last
  asked for). The switch is bound to *user intent*, not to live state. If the live
  state is Paused-system, the switch shows ON but the status pill shows the system
  pause.

### 3.2 One Bridge, one row — even when it's two backend tunnels

If host H and joiner J are actively cascading and the user created them as part of an
onboarding "set up a relay" flow, they're presented as one row titled "*Home ↔ Work*"
with a stacked-arrow icon. Tapping reveals both component tunnels in the detail
screen.

If they happened to cascade as a side effect of two independently-created tunnels,
they remain two rows but each row's detail screen calls out the cascade relationship
("This tunnel is currently relaying traffic to *Work VPN*. [Stop relaying]").

The discriminator is a per-tunnel `groupId: UUID?`. The relay-setup flow assigns a
shared groupId; manual setup leaves it null. The UI checks `groupId` to decide
single-row vs. two-row presentation. This keeps the underlying model honest (cascade
is still an emergent property of overlapping AllowedIPs) while letting us collapse
deliberately-paired tunnels for clarity.

### 3.3 What we delete from the existing screen

- The "host mode" section header.
- The separate `HostModeSection.kt` composable.
- The implicit "joiner tunnels go on top, host tunnels on the bottom" layout.
- Any text that says "joiner" or "host" outside the diagnostic surface.

---

## 4. TunnelDetail: a transcript, not a form

The detail screen has two zones:

**Top (always visible):** the Connection's name, big status pill, primary action
button (Connect / Disconnect / Reconnect / Fix). Below that, three single-line facts:
- "Reaches: 10.0.0.0/24, 192.168.50.0/24" (the AllowedIPs in human terms)
- "Through: cellular" / "Wi-Fi (Home-5G)" / "any network" (the chosen underlying
  transport, observed via NetworkCallback, not user-configured)
- "Last handshake: 7 s ago" / "no traffic yet" / "47 minutes ago — stale"

**Below the fold (collapsed by default; "Show technical details"):**
- the WireGuard config in canonical form (peer pubkeys, endpoints, port)
- the gvisor route table for this tunnel
- live counters: rx/tx bytes, dropped same-uid, dropped invalid-pubkey
- the state-machine transition log (last 50 events with timestamps) — this is the
  killer diagnostic for handoff to the maintainer
- "Edit raw config" button (for the 1% who want it)

### 4.1 Failure diagnostics — be specific or be silent

Every Failed state carries a structured `FailureCause` enum and a `humanMessage`. The
status pill is tappable when red; tapping shows the explanation in plain English
plus a one-tap remediation when possible:

| Cause | Message | Remediation |
|---|---|---|
| `ConsentDenied` | "Android didn't grant permission for this connection. Tap to ask again." | re-launch `VpnService.prepare()` |
| `PortInUse(port, holderUid?)` | "UDP port 51820 is busy. Another VPN app is probably using it." | offer port reassignment if host mode |
| `PeerKeyRejected` | "The other side rejected this connection's identity. The remote server may have removed this device." | open Edit |
| `HandshakeTimeout(endpoint)` | "Couldn't reach the server at 1.2.3.4:51820. Last seen 4 minutes ago." | offer wormhole re-pair |
| `RoutingLoopDetected(otherClient)` | "Another WireGuard app on this device is routing through *this* tunnel, which would create a loop. Open ChromeOS WG settings and either remove the route to this device or disable that tunnel." | deep-link to ChromeOS settings if ARC; otherwise instructions only |
| `CascadePolicyBlocked` | "This is set to not relay. Tap to allow." | flip relay policy |

The state-machine transition log is the diff between what happened and what the user
expected. When users report bugs, we ask them to share it.

---

## 5. Onboarding & discovery

### 5.1 The first run

A first launch shows **three tiles**, not a list:

1. **"Join a network"** — paste a config, scan a QR, paste a wormhole code, or
   discover via Bonjour (when on the same Wi-Fi as a daemon-running peer).
2. **"Share my network"** — set up host mode. The flow is "what should your friends
   reach?" not "configure host mode AllowedIPs".
3. **"Bridge two networks"** — the discovery surface for use case C. This tile
   walks the user through joining a remote network *and* sharing it with local
   peers in one flow. At the end, the two created tunnels share a `groupId` and
   appear as one Bridge row.

Tile #3 is how use case (C) gets discovered. Without it, "bridge" is invisible
no matter how clean the runtime behavior is.

### 5.2 Contextual hint after the fact

If a user creates Tile-#1 and Tile-#2 independently, and the resulting AllowedIPs
overlap (rule §2.1), we surface a one-shot banner on the next app open:

> "*Home* and *Work* could be bridged — devices on Home would gain access to Work.
> [Set up Bridge] [Not now] [Don't ask again]"

This is the closest we get to discovery for users who didn't take the onboarding
path. We sticky the dismissal.

### 5.3 No tour, no carousel

I considered a "what wgrtc can do" tour. Rejected: tours train users to dismiss
modals. The three-tile first run + the contextual banner is enough discovery
surface.

---

## 6. Diagnostic surface

### 6.1 The phantom-active failure (use case G)

Fixed structurally by §1.2's `onRevoke` → `Paused (system)` transition. The service
emits the event before calling `stopSelf()`, the registry updates, the row redraws.
Implementation cost: override `JoinerNVpnService.onRevoke()`, call
`controller.notifyRevoke()` then `super.onRevoke()`. ViewModel observes a
`SharedFlow<TunnelId>`. ~30 lines of Kotlin.

### 6.2 The ChromeOS routing-loop case (use case D)

We **cannot** read the ChromeOS-native WG client's configuration. But we can probe
before bringing up a host tunnel:

1. Bind a UDP socket inside our gvisor netstack to `0.0.0.0:listen_port`.
2. From an OS socket *outside* the netstack (real-Android scope), send a magic UDP
   datagram to our own public IP on `listen_port`.
3. If the datagram lands in gvisor: there's no loop (the ChromeOS-native client is
   not routing our IP through us).
4. If the datagram lands in gvisor *via the joiner tunnel* (we tag it with the
   netstack it came through): loop detected — `RoutingLoopDetected`.
5. If neither (timeout): no loop, but no inbound reachability either; that's a
   different (recoverable) failure.

The probe is cheap (one datagram), runs once at Arming, and is the only way to catch
this class of bug before the user's network falls over. The brief lists this as
"impossible" with caveats — the probe above is **possible** because we control both
endpoints. We cannot diagnose the loop after it happens (no inbound packets means no
callback), so the prevention is at Arming time.

If the probe is not feasible on a given device (no inbound port, CGNAT), we fall
back to a softer warning: "If you have another WireGuard client running on this
device with AllowedIPs covering 1.2.3.4, it will create a routing loop. Continue?"

### 6.3 The everything-else case

The transition log (§4) is the universal answer. Every failure becomes a story:
"Disabled → Arming → Failed (recoverable) — port 51820 held by uid 10184". The user
forwards the log; the maintainer reads it; the diagnosis takes 30 seconds.

---

## 7. The wild-idea reframing: Connections, not Tunnels

Already developed above. To restate it crisply:

The user-facing model is a **Connection**: a directed reachability claim between
"this phone" and "a set of addresses", with a direction (in / out / both) and a
status. The Connection does not have a "mode". The implementation chooses
VpnService vs. userspace UDP listen based on the direction:

- direction = out → joiner via VpnService (joins joiner-N)
- direction = in → host via userspace
- direction = both (Bridge) → both, with cascade auto-installed

A Bridge is a first-class Connection-of-Connections. The user can create one with a
single name ("Home ↔ Work"), the app spawns the two underlying tunnels, gives them a
shared `groupId`, and the TunnelList shows one row.

The wild part: the user can drag a Connection on top of another Connection to
*compose* them into a Bridge. The address-space overlap check runs; if it would
work, the rows merge with an animation; if it wouldn't (joiner doesn't cover what
host needs), we explain why. Drag is overkill for a touch-only UI most of the time,
but the underlying operation (compose two connections into a bridge) is a single
gesture and that gesture is the only place "cascade" needs to be a noun.

For Pixel-class hardware (no large screen), the drag affordance is replaced with a
long-press "Bridge with..." menu item on each row.

---

## 8. Feasibility check

| Claim | Engineering work | Confidence |
|---|---|---|
| §1.2 onRevoke wired to ViewModel | Override `onRevoke()` in `JoinerNVpnService`, emit on a process-wide `SharedFlow`. Replace `_activeJoinerNTunnelIds` reads in `TunnelListViewModel` with subscription to the new registry. | High; ~30 lines. |
| §1.3 derived state from `lastHandshakeTime` | Poll already exists at 5 s. Add `HANDSHAKE_STALE_SEC = 180` (matches WG RekeyAttemptTime semantics). | High. |
| §2.1 automatic cascade | Already implemented in CASCADE-2; just remove the global gate and add per-tunnel `relayPolicy` (Always / Never / Ask). | High; the hard part is done. |
| §2.3 default-Block for full-tunnel joiners | Inspect `peers[*].AllowedIPs` for `0.0.0.0/0` or `::/0` at peer-set load; set `relayPolicy=Never` unless user overrides. | High. |
| §3.2 single-row Bridge presentation | Add `groupId: UUID?` to tunnel storage. TunnelListViewModel groups by `groupId`. | High; minor schema change. |
| §4 transition log | Wrap state transitions in a ring buffer per tunnel. Surface in detail screen. | High. |
| §5.1 Tile-#3 "Bridge two networks" flow | New composable; orchestrates two existing flows (join + host) and assigns shared `groupId`. | High; pure UI. |
| §6.2 routing-loop probe | Emit a datagram from an OS-scoped socket to `public_ip:listen_port`; tag arrival in gvisor by which `channel.Endpoint` delivered it. Need our public IP — STUN call we already make for endpoint advertisement. | Medium. Failure modes: CGNAT, IPv6-only egress, restrictive firewalls. Fall back to soft warning. |
| §6.1 specific port-conflict cause | Need to know which uid holds the port. `/proc/net/udp` is readable in Android up to API 28; on newer APIs we cannot get peer uid without `INTERNET_USAGE` (we don't have it). | **Low**. Will probably ship as "port in use" without naming the holder. The critic should push on this. |
| §7 drag-to-bridge | Compose drag-and-drop is mature. Long-press menu is the fallback on phones. | High for the gesture; the UX *value* is medium — long-press menu is probably enough. |

### Things I claim are impossible

- **Reading ChromeOS-native WG client config**: confirmed in the brief, confirmed
  by our own packet captures. We can warn after seeing pathological traffic; we
  cannot warn pre-emptively except via the §6.2 probe.
- **Per-joiner VpnService consent**: the brief locks this. The UX consequence:
  consent is a one-shot per applicationId, and once granted, all joiners under that
  buildType inherit. We surface this honestly in onboarding ("Granting permission
  here lets *any* connection in wgrtc act as a VPN"). No bypass.
- **Routing the wgrtc app's own traffic through its own joiner**: Android refuses;
  the brief is correct. UX consequence: `host_forwarder` traffic visibly skips the
  joiner. We document this in Detail under "Through: doesn't route through *Work
  VPN*" with a small info icon.

---

## 9. Open questions for the reviewer

1. **The "Connection" rename.** Does collapsing host/joiner into one noun lose
   information that power users need? The diagnostic surface still exposes both
   words. Is that enough?
2. **§2.3 default-Block for full-tunnel joiners.** Is the address-space heuristic
   (presence of `0.0.0.0/0`) a good-enough proxy for "this is sensitive"? What
   about a `10.0.0.0/8` joiner pointing at a corporate WAN?
3. **§3.2 single-row Bridge vs. two rows.** Does the `groupId` discriminator
   actually help, or does it just create a second presentation that the user has
   to learn? Should we always show two rows and let cascade be visible only in
   detail?
4. **§5.1 Tile-#3 discoverability.** Is "Bridge two networks" a self-explanatory
   tile title to a non-technical user, or do we need a sub-line? ("Share a remote
   VPN with devices on your local Wi-Fi.")
5. **§6.2 routing-loop probe.** Is the latency cost (one round-trip at every host
   tunnel Arming) acceptable on cellular where the probe might take 2-3 s? Should
   we run it async and let the tunnel come up optimistically, only tearing it down
   if the probe fails?
6. **State alphabet size.** Eight states. Too many? `Idle` is the suspicious one —
   does the distinction between Connected and Idle matter to users, or just to us?
7. **The drag-to-bridge gesture.** Phone-first means thumb-reachable. Drag across a
   list is awkward thumb work. Is the long-press menu the *only* affordance and the
   drag a developer-screen-recording fantasy?
8. **Onboarding tile #2 "Share my network".** Most users *should never see this*
   because the use case is rare and the loop hazards are real. Should it be hidden
   behind a "More options" gesture, or is the diagnostic surface (§6.2) protective
   enough that we can show it at the top level?
9. **The `relay: never` policy.** Per-tunnel or per-(host, joiner) pair? Per-pair
   is more precise but requires an N×M settings surface. Per-tunnel is easier to
   reason about.
10. **Permanent-vs-recoverable failure classification.** `PeerKeyRejected` is in
    permanent; should it be recoverable so the next reconnect attempts? Same for
    `ConsentDenied` — Android sometimes re-prompts after a system update; do we
    want to auto-recover or stay permanent until the user re-taps?

---

## 10. What this design deletes

For the reviewer to push back on, here's what we're proposing to *remove*:

- Global cascade toggle in Settings.
- "Host Mode" as a user-facing concept and the `HostModeSection` composable.
- Implicit ordering of joiners-then-hosts in TunnelList.
- The current single-state "active / inactive" boolean in `TunnelListViewModel`.
- Any UI string containing the words "joiner" or "host" outside the diagnostic fold.
- The current `OnboardingFlow` (which mostly punts to a tunnel-list with a `+`
  FAB); replaced by the three-tile first run.

What we keep:
- The wormhole pairing flow (it's good and orthogonal).
- The QR / paste / manual config paths (folded under Tile #1).
- The OfferListener foreground notification — but with the status pill updated live.
- The Edit raw config escape hatch (under "technical details").

---

## 11. Implementation order (rough)

1. **Land the state machine + transition log.** Pure-Kotlin; pure-JVM testable.
   Don't change any UI yet. Subscribe diagnostic logging to it. (Pain point #2 and
   #7 are partially fixed just by this.)
2. **Wire onRevoke through the registry.** Phantom-active failure dies.
3. **Remove the global cascade toggle.** Replace with per-tunnel `relayPolicy`
   defaulted by the §2.3 rule.
4. **Repaint TunnelList rows.** Direction badges, status pills, no "host" word.
5. **Repaint TunnelDetail.** Transcript view, specific failure messages.
6. **Three-tile first run.** Tile #3 is the headline.
7. **Routing-loop probe.** Behind a feature flag in `.debug` first.
8. **`groupId` and single-row Bridge presentation.** Last because it requires
   schema migration.

Each step is independently shippable. Steps 1–2 alone resolve the most painful
brief items.

---

*End of v1. Hand this to the critic; iterate.*
