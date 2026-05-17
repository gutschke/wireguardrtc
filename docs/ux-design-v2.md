# wgrtc UX Design v2 — "Connections, not Configs"

Status: round-2, addressing the round-1 critique
Audience: maintainers + critic (diff-review)
Scope: phone-first Android UI. ARC-on-Chromebook is a secondary target.

---

## Round-2 changes summary

**Must-fixes (all 5):** §1.2 phantom-active detection rewritten around
`establish()`-null + foreground `prepare()` re-check (the actually-firing
signals); §1.2 gains `Idle → Connecting`; §2.1 rule (2) rewritten for the
asymmetric host→joiner cascade; §2.3 default flipped to Block (no heuristic);
§6.2 active probe replaced with passive ChromeOS-Settings deep-link.

**Should-fixes (6):** §7 drag-to-bridge cut; switch + Paused-user reconciled
to one control; freshly-imported = `Disabled`; `BrokerMissing` cause +
broker URL surfaced; WG-constant fixed (180 s = `RejectAfterTime`); throughput
cadence fixed (1 s, not 5 s — `WgrtcViewModel.kt:1868`).

**Nice-to-haves:** Bonjour dropped from §5.1; `humanMessage` noted as
`@StringRes` in §4.1.

**Loose ends:** §1.4 (new — FGS while all paused); §3.2 (groupId orphans);
§2.4 (`Ask` row presentation); §1.1 (`Pairing` state for wormhole transients);
§4.1 (`ConsentSilentlyDenied`); §4 (dropped-same-uid = packets); §11 (N hosts);
§12 (new — schema migration); §13 (new — rollback / regression kill-switch).

**Pushback:** critic's Attack 2 framed cascade as "fully one-directional".
The ferry installs routes both ways inside gvisor
(`cascade_ferry_registry.go:266-294`); only the user-visible admit-direction
is asymmetric. §2.1 explains. Critic's "the toggle is the only knob preventing
accidental relay on CASCADE-2 regressions" gets a structural answer in §13.

---

## 0. One-paragraph thesis

The current app exposes WireGuard's mental model: a tunnel is a config object, with
a hidden "cascade" toggle that might make two of them talk to each other. Real users
have **destinations** they want to reach and **services** they want to publish.
Everything else — host vs. joiner, VpnService vs. userspace socket, cascade route
insertion — is plumbing. This redesign promotes the plumbing's *effects* to
first-class objects (a **Connection** is a directed reachability claim; a **Bridge**
is what the app composes automatically when two connections cover the same address
space) and demotes the plumbing itself to a diagnostic surface that only appears
when something is wrong.

The load-bearing change is **a single authoritative state machine per tunnel**,
driven by every observable signal the JNI / VpnService / NetworkCallback surfaces
actually expose — and the ViewModel subscribes to *that*, not to whichever knob the
user last touched.

---

## 1. Tunnel state model — the load-bearing part

**Changed since v1:** alphabet grows by one (`Pairing`); `Idle → Connecting`
transition added; `onRevoke` row replaced by the actually-firing signals; throughput
cadence and WG-constant attribution corrected; freshly-imported start state
specified.

Every tunnel — host or joiner, single or part of a relay — owns one instance of the
following state machine. The ViewModel observes a `StateFlow<TunnelState>` and the
UI never inspects backend booleans directly.

### 1.1 States

```
Disabled            saved, not asked-for. Freshly-imported tunnels (paste, QR,
                    wormhole completion) land here; import does NOT auto-Connect.
Pairing             wormhole-pairing in flight (SAS, key derivation, enrollment).
                    Pre-tunnel: no UDP socket yet. → Disabled on success, →
                    Failed(permanent) on user-abort / SAS-mismatch.
Arming              user tapped Connect; gathering consent, port bind, key load.
Connecting          preconditions satisfied; handshake in flight.
Connected           handshake < 180 s ago AND bridge alive AND consent valid.
Idle                Connected-by-config but no recent handshake (joiner with no
                    traffic and no keepalive; not a fault).
Degraded            handshake stale but socket alive; auto-recovery in progress.
Paused (system)     Android revoked VpnService OR another VPN took over OR Doze
                    killed the foreground service.
Paused (user)       user flipped the row switch off; sticky across reboots.
Failed (recoverable) handshake never landed / port collision / endpoint
                    unreachable; next network event re-arms.
Failed (permanent)  consent denied, key material corrupt, peer pubkey rejected,
                    routing-loop user-confirmed; requires user action.
```

Nine states. `Pairing` is the round-2 addition the critic asked for —
wormhole transients don't have a UDP socket yet, so they don't fit Arming
or Connecting. Modelling it lets the UI show progress during SAS exchange.

**Freshly-imported tunnel**: `Disabled`. The switch (§3.1) reflects user intent;
a never-asked-for tunnel reads off.

### 1.2 Signals and transitions

| Signal | Source | Effect |
|---|---|---|
| `builder.establish()` returns null | `JoinerVpnService.kt:108-110`, `JoinerNVpnService.kt` analogue | All joiners → `Paused (system)`. **This is the ground-truth signal for permission revocation** — both the "user toggled VPN permission off in Settings" and "force-stopped" cases are caught here on the next connect attempt. |
| `VpnService.onRevoke()` callback | new override on `JoinerNVpnService` | All joiners under this service → `Paused (system)`. Covers only the "another VPN app took over" case; covers it cheaply. **Not** sufficient on its own (does not fire on Settings-revoke or force-stop). |
| `MainActivity.onResume()` → re-`VpnService.prepare()` | Activity-scope foreground hook | If `prepare()` returns a non-null consent Intent while any joiner row was previously rendered Connected, transition all joiners to `Paused (system)` immediately. Catches the Settings-revoke case at the next foreground without waiting for the user to tap Reconnect. |
| `lastHandshakeTime` poll @ 1 s | `WgrtcViewModel.kt:1868` (already exists) | Connecting → Connected on first non-zero handshake; Connected → Idle after `HANDSHAKE_STALE_SEC = 180` (this is `RejectAfterTime` in the WG state machine, **not** RekeyAttemptTime). |
| Outbound packet observed on gvisor write side | host_forwarder / joiner channel.Endpoint Write callback | Idle → Connecting. Re-uses the existing per-NIC packet counter; threshold = "any non-zero delta since last poll". |
| Endpoint reconfigure (signaling delivered a new endpoint) | offer-listener | Idle → Connecting if currently Idle; also clears Degraded. |
| User foregrounds the detail screen for an Idle tunnel | ViewModel | Idle → Connecting (forces a keepalive nudge — same code path as the manual Reconnect button). Cheap, single UDP packet, and exactly the moment the user wants to know whether the tunnel still works. |
| `ConnectivityManager.NetworkCallback.onLost` / `onAvailable` | system | Connected → Degraded → Connecting (auto re-arm). |
| Peer-set delta from offer-listener | WSS endpoint roam | does not change state; updates endpoint, may unblock Degraded. |
| Port bind EADDRINUSE | host mode UDP bind | Arming → Failed (recoverable). The conflicting-holder uid is **not** identified by the UI today (see §6.1 honesty paragraph). |
| ChromeOS routing-loop user-confirmation (see §6.2) | passive dialog | Arming → Failed (permanent) with the loop diagnosis. |
| Same-uid traffic dropped | gvisor netstack stat (packet counter; see §4 unit clarification) | informational only — never a state change, surfaced in detail view. |

### 1.3 Two invariants

**Invariant 1: the ViewModel is downstream of the service, never upstream of it.**
Today, `_activeJoinerNTunnelIds` is a `MutableStateFlow` mutated by the UI when the
user taps Connect, and *also* read by the UI to draw the row. When the system revokes
consent, the service dies but the flow never gets updated. We invert this: the
service owns a `TunnelStateRegistry` (process-wide, in-memory, rebuilt from UAPI on
service start), and the ViewModel **only reads** from it. The Connect button posts a
command to the service; the service mutates the registry; the registry emits; the UI
redraws.

**Invariant 2: state is derived, not stored.** `Connected` is the result of
`lastHandshakeTime > now - 180s AND service.bridgeAlive(id) AND !consentRevoked(id)`.
If any flips, the derived state flips on the next emission. The emission cadence is
1 s today (`WgrtcViewModel.kt:1868`) — the design accepts that worst-case state
freshness is ~1 s and does not try to make derivation packet-synchronous.

### 1.4 FGS notification while every tunnel is paused

**Changed since v1:** addresses critique loose end on OfferListener FGS.

The OfferListenerService FGS exists to keep the WSS alive for *Connected*
tunnels and for *host* tunnels awaiting inbound offers. Policy:

- If any host tunnel is Connected, or any joiner is Connected / Connecting /
  Degraded / Idle, FGS persists.
- If every tunnel is in {Disabled, Paused (user), Failed (permanent)}, FGS
  posts a "paused — all connections off" notification, suspends the WSS read
  loop, but stays alive (so user pause-stickiness is observable). The
  notification offers a one-tap Resume that flips the last-active set back on.

Honest about what the service is doing; the alternative (silently keep the WSS
alive) is invisible battery drain.

---

## 2. Cascade: no toggle, ever

**Changed since v1:** rule (2) rewritten against the actual asymmetric cascade.
§2.3 default flipped to Block. §2.4 added for `relayPolicy: Ask` rendering.

Drop the global Settings toggle. Cascade is not a feature; it's an emergent property
of two Connections covering the same address space — but **only in the direction
the implementation supports**.

### 2.1 The rule (rewritten)

**Pushback on the critic's framing**: the critic asserted cascade is "fully
one-directional, host → joiner". Slightly inaccurate.
`cascade_ferry_registry.go:266-294` installs routes in **both directions inside
the gvisor ferry** — host-side routes for joiner AllowedIPs (lines 278-288),
joiner-side routes for the host's peer subnets (lines 291-293). The asymmetry is
at the user-visible level: only the host's enrolled peers admit new flows. The
joiner can't originate cascade flows because joiner-side WG peers (typically a
remote server) don't have routes back to the host's enrolled-peer /32s.

Restated cleanly: a **cascade route from host H to joiner J** is installed when:

1. H and J are both `Connected` (not Idle, not Degraded).
2. There exists a peer P enrolled on H whose decrypted traffic targets an address
   ∈ ⋃(J.peers[*].AllowedIPs). This is exactly what `HasCascadePrefix` tests
   inside the ferry registry (`docs/cascade-2-plan.md` §5).
3. H's `relayPolicy` is not `Never`.

The route is torn down the moment J leaves `Connected`. The drop-NIC mechanism
(`cascade_ferry_registry.go:297-309`) already handles the gap window without
leaking through host_forwarder's catchall.

**No "drag joiner onto joiner" gesture exists.** §7 is cut.

### 2.2 Why not a toggle

A toggle requires the user to know what cascade is, that they want it, and to
revisit Settings whenever they add a new tunnel. The brief's pain point #1 is
real. Three costs paid every install; benefit zero in the simple-joiner case
(majority). The critic conceded this in Win #1 and we keep the argument intact.

The toggle is replaced by per-tunnel `relayPolicy: Always | Never | Ask`,
stored on the host tunnel (the side that admits cascade traffic, per §2.1).

### 2.3 Default policy (changed)

**Changed since v1:** v1's heuristic ("Block for `0.0.0.0/0`, Allow otherwise")
missed the critic's Scenario B (corporate WAN with `10.0.0.0/8` joiner — the
exact privacy-leak the heuristic exists to catch). Round-2: no heuristic.

A new host tunnel starts with `relayPolicy = Ask`. The first time a Connected
joiner is cascade-eligible (per §2.1 rule 2), the host's row shows a one-shot
banner:

> "Devices on *Home* could now reach addresses covered by *Work VPN*.
> [Block always] [Allow once] [Allow always]"

Block-always is the leftmost option (LTR-prominent, safe default). Until the
user taps something, cascade is **not** installed — `Ask` is fail-safe.
"Allow once" installs cascade for this process lifetime; the banner re-appears
next launch. "Allow always" / "Block always" set the policy permanently.

No address-space heuristic. Privacy decisions are explicit.

### 2.4 What `relayPolicy: Ask` renders as

**Changed since v1:** addresses §8 critique loose-end.

The row's status pill always reflects the host tunnel's own connection state —
`Ask` is invisible there. The banner is a separate widget under the row, shown
only while a (host, joiner) pair is eligible. The three buttons above are the
only dismissal paths; ignoring is the safe default (fail-safe Block, see §2.3).

With multiple cascade-eligible joiners running (Joiner-N), the banner
enumerates: "Devices on *Home* could now reach addresses covered by *Work VPN*
and *Lab Cluster*." A single decision applies to all currently-Connected
joiners; the next joiner to come up re-prompts.

---

## 3. TunnelList: the row is a Connection

### 3.1 Reframing: kill "host" and "joiner" as user-facing words

**Changed since v1:** the row's switch and the alphabet's `Paused (user)` are
now reconciled. There is exactly one pause-with-intent control: the **switch**.

Show **Connections**. A Connection has:

- a **name** (user-given or imported from config)
- a **direction badge** (small icon, not text):
  - arrow into a phone glyph = inbound (host)
  - arrow out of a phone glyph = outbound (joiner)
  - two arrows = bridge (host + cascade-active joiner)
- a **status pill** drawn from §1's state alphabet, color-coded:
  - green Connected, gray Idle, amber Degraded/Paused-system, blue Paused-user,
    red Failed-recoverable, dark red Failed-permanent, neutral Disabled, violet Pairing
- a **right-side switch** that toggles between Disabled/Paused-user and "user
  wants this on". The switch is bound to *user intent*. If live state is
  Paused-system, the switch shows on but the status pill shows the system
  pause. Tapping the switch off when state is Paused-system writes
  `intent=off` (the Resume button no longer prompts on reboot).
- **Tap the row** = navigate to detail. Tap is never a state change — that's
  the switch's job.

The single control = single semantic resolves the critique's "two pause-with-intent
semantics on two controls" concern.

### 3.2 One Bridge, one row — even when it's two backend tunnels

**Changed since v1:** spells out groupId-orphan handling.

Tunnels created via the §5.1 Tile-#3 flow share a `groupId` and present as one
row titled "*Home ↔ Work*" with a stacked-arrow icon. Tapping reveals both
component tunnels in detail. Tunnels that cascade by side effect of independent
creation remain two rows; each row's detail calls out the relationship
("This tunnel is currently relaying traffic to *Work VPN*. [Stop relaying]").

**`groupId` orphan handling**: on every TunnelList load, group by `groupId`.
A group of size 1 with a non-null `groupId` renders as a normal single tunnel
(null-coalesced for rendering; persisted value is left alone — cheap to keep,
useful if the deleted half returns via Import). During half-Bridge teardown
(one half Disconnects but is still saved) the row stays single-row showing
the Bridge name with the surviving half's state pill. The critic's "what's
the row count?" answer: always **one row per surviving tunnel**, group-collapsed
only when a sibling is also present.

### 3.3 What we delete from the existing screen

- The "host mode" section header.
- The separate `HostModeSection.kt` composable.
- The implicit "joiner tunnels go on top, host tunnels on the bottom" layout.
- Any text that says "joiner" or "host" outside the diagnostic surface.

---

## 4. TunnelDetail: a transcript, not a form

**Changed since v1:** transition log stays (critic's Win #2); below-the-fold
gets `dropped same-uid` units, broker URL, and an honest note about the
gvisor-route-table dump being a future JNI add.

The detail screen has two zones:

**Top (always visible):** Connection name, big status pill, primary action button.
Below: three single-line facts:

- "Reaches: 10.0.0.0/24, 192.168.50.0/24" (AllowedIPs in human terms).
- "Through: Wi-Fi (Home-5G)" / "cellular" — observed via `NetworkChangeMonitor`'s
  `default` callback (`data/NetworkChangeMonitor.kt:44-82`). The `filtered`
  callback (egress policy selection) appears only in the technical fold; v1
  prose conflated them.
- "Last handshake: 7 s ago" / "no traffic yet" / "47 minutes ago — stale".

**Below the fold ("Show technical details"):**

- WG config in canonical form (peer pubkeys, endpoints, port).
- **Broker URL** the OfferListener is using. Surfacing this fixes the critic's
  Scenario A — the user who deletes their broker by hand now has a visible
  answer.
- Live counters: rx/tx bytes; dropped same-uid as **packet count** (gvisor
  `Stats.NICs[*].Rx.PacketsDropped`, addressing the critic's units loose-end);
  dropped invalid-pubkey count.
- gvisor route table — **honest note**: no JNI export dumps routes today
  (`WgBridgeNative.kt` has 6 methods, none for routes). Lowest-priority field;
  ships if cheap, else dropped.
- State-machine transition log (last 50 events with timestamps). Highest-payoff
  diagnostic; the user copies it, the maintainer reads it.
- "Edit raw config" button for the 1%.

### 4.1 Failure diagnostics — be specific or be silent

**Changed since v1:** adds `BrokerMissing`, `ConsentSilentlyDenied` (Android 14+
case), notes on `humanMessage` i18n.

Every Failed state carries a structured `FailureCause` enum and a `humanMessage`.
The status pill is tappable when red; tapping shows the explanation in plain
English plus a one-tap remediation when possible:

| Cause | Message | Remediation |
|---|---|---|
| `ConsentDenied` | "Android didn't grant permission for this connection. Tap to ask again." | re-launch `VpnService.prepare()` |
| `ConsentSilentlyDenied` | "Android is silently refusing the VPN permission for this app. Open System Settings → Apps → wgrtc → Permissions to clear the denial." | deep-link to App Info |
| `PortInUse(port)` | "UDP port 51820 is busy. Another VPN app is probably using it." | offer port reassignment if host mode |
| `BrokerMissing` | "No signaling server configured. Open Settings to restore the default broker or paste your own." | deep-link to Settings → Broker |
| `BrokerUnreachable(url)` | "Can't reach the signaling server at `wss://…`. Check your internet connection." | retry button (re-arms the WSS) |
| `PeerKeyRejected` | "The other side rejected this connection's identity. The remote server may have removed this device." | open Edit |
| `HandshakeTimeout(endpoint)` | "Couldn't reach the server at 1.2.3.4:51820. Last seen 4 minutes ago." | offer wormhole re-pair |
| `RoutingLoopUserConfirmed` | "You confirmed another WireGuard client routes through this tunnel's outer transport. Disable that client first." | deep-link to ChromeOS settings on ARC; otherwise instructions only |
| `CascadePolicyBlocked` | "This is set to not relay. Tap to allow." | flip relay policy |

**`ConsentSilentlyDenied` is the Android 14+ case** the critic flagged — `prepare()`
returns a non-null intent, but launching it silently no-ops because the user has
toggled the permission off at the App-Info level. We detect this by: if
`consentLauncher.launch()` returns without a result within a short window
(`MainActivity.kt:485-491` is the existing call-site), treat it as silent denial
and route to App-Info.

**`humanMessage` i18n**: the `humanMessage` field is an Android string resource ID,
not a literal `String`. Each `FailureCause` constructor takes a `@StringRes` and
the format args. This is mechanical and adds no structural complexity; mentioning
it for completeness against the critic's recommendation 13.

The state-machine transition log is the diff between what happened and what the
user expected. When users report bugs, we ask them to share it. The critic was
right that this is the highest-payoff item; nothing here is reduced.

---

## 5. Onboarding & discovery

### 5.1 The first run

**Changed since v1:** Bonjour bullet dropped. Tile #1 paths are paste / QR /
wormhole only.

A first launch shows **three tiles**, not a list:

1. **"Join a network"** — paste a config, scan a QR, or paste a wormhole code.
   (No Bonjour. The critic was right that NSD/mDNS would be a separate spec;
   not in scope here.)
2. **"Share my network"** — set up host mode. The flow is "what should your
   friends reach?" not "configure host mode AllowedIPs".
3. **"Bridge two networks"** — the discovery surface for use case C. This tile
   walks the user through joining a remote network *and* sharing it with local
   peers in one flow. At the end, the two created tunnels share a `groupId` and
   appear as one Bridge row.

Tile #3 is how use case (C) gets discovered. Without it, "bridge" is invisible
no matter how clean the runtime behavior is.

**Scope honesty**: replacing the current `OnboardingScreen` (a three-page pager,
`ui/OnboardingScreen.kt:62`) with a three-tile launcher is a moderate-size UI
change, not a "pure UI nit" rewrite. Estimate is 300-500 LOC plus the Tile #3
flow itself.

### 5.2 Contextual hint after the fact

If a user creates Tile-#1 and Tile-#2 independently, and a host's enrolled-peer
traffic begins matching a joiner's AllowedIPs (rule §2.1), the §2.3 banner does
the discovery. There is no separate "would you like to bridge?" banner — the
relay-policy decision is the only nudge the user gets.

### 5.3 No tour, no carousel

I considered keeping the v1 onboarding tour. Rejected: tours train users to
dismiss modals. Three-tile first run + §2.3 banner is enough discovery surface.

---

## 6. Diagnostic surface

### 6.1 The phantom-active failure (use case G)

**Changed since v1:** three signals, not one callback; honest LOC.

The phantom-active failure is fixed by the combination of:

1. `builder.establish()` returns null on next Connect → emit
   `RevokeEvent(ESTABLISH_NULL)`, all joiners → `Paused (system)`. **Dominant
   ground-truth signal**; existing code already hits this site
   (`JoinerVpnService.kt:108-110`) — we add the registry emission, not the
   detection.
2. `VpnService.onRevoke()` override → emit `RevokeEvent(ANOTHER_VPN)`. Covers
   the competitor-VPN takeover case cheaply.
3. `MainActivity.onResume()` re-runs `VpnService.prepare()`; if non-null while
   any joiner is "intended on", emit `RevokeEvent(FOREGROUND_RESYNC)`. Catches
   the Settings-revoke case at next foreground without user action.

**Implementation cost (honest)**: ~120-180 LOC, not "~30 lines". Split across
the two services (~40 LOC), `MainActivity` (~30), a new `TunnelStateRegistry`
(~80), and the ViewModel subscription rewrite (~30), plus tests at each layer.
The v1 estimate was wrong.

### 6.2 The ChromeOS routing-loop case (use case D)

**Changed since v1:** active probe abandoned (Attack 4 was right — needs
inbound public reachability the host-mode-on-mobile cohort rarely has, and
needs a per-NIC arrival-tag JNI export that doesn't exist). Replaced with a
passive yes/no.

At Arming time for any host tunnel on ARC, show a one-shot dialog
(sticky-dismiss per host tunnel):

> "If another WireGuard client on this Chromebook routes traffic to this
> device's IP through itself, your network may form a loop. We can't check
> from inside the app. **Open ChromeOS Settings → Network → VPN** to verify
> no tunnel has this device's IP in its AllowedIPs.
> [Open Settings] [I've checked — continue] [Cancel]"

Cancel → `Failed (permanent, RoutingLoopUserConfirmed)`. "I've checked" →
proceed, never warn again for this host. Open Settings deep-links via
`Settings.ACTION_VPN_SETTINGS` (works on ARC; same pattern as the joiner
consent flow). On non-ARC Android the dialog is suppressed.

No JNI work, no round-trip latency at Arming. Same diagnostic value as the
original probe, whose success path was already the rare cohort.

### 6.3 The everything-else case

The transition log (§4) is the universal answer. Every failure becomes a
story: "Disabled → Arming → Failed (recoverable) — port 51820 busy". The user
forwards the log; the maintainer reads it; the diagnosis takes 30 seconds.
This is the design's highest-confidence single deliverable.

---

## 7. *(deleted)*

**Cut since v1.** The §7 "drag-to-bridge" gesture is removed. As the critic
noted, dragging a joiner onto a joiner can't compose them into a bridge
(cascade is host→joiner, not joiner↔joiner). Dragging a joiner onto a host
matches the real direction but the affordance is awkward on phone-class
hardware (§9.7 open question already admitted that).

The replacement: a long-press menu item on each row, **"Bridge with…"**,
which opens a single-select list of *compatible* tunnels. Compatibility is
the §2.1 rule applied symbolically — pick a host, the list shows joiners
whose AllowedIPs would cover at least one of its enrolled-peer destination
ranges. Pick a joiner, the list shows hosts. Selecting writes a shared
`groupId` to both, optionally renames them to `Source ↔ Sink`, and the §2.3
banner fires at the next connection event to confirm the relay decision.

This is the single user gesture that promotes "compose two connections
into a bridge" to a first-class operation, replacing the deleted drag.

---

## 8. Feasibility check

**Changed since v1:** honest LOC for the §6.1 fix; §6.2 changed from
"Medium" to "Low" (no JNI work); §3.2 groupId schema cost surfaced at ~50 LOC
not "minor"; §5.1 onboarding cost surfaced.

| Claim | Engineering work | Confidence |
|---|---|---|
| §1.2 phantom-active fix (3 signals) | ~120-180 LOC across services + Activity + new registry + ViewModel. Tests at each layer. | High; honest size now. |
| §1.3 derived state from `lastHandshakeTime` | Poll already exists at 1 s. Add `HANDSHAKE_STALE_SEC = 180` (matches `RejectAfterTime`, not RekeyAttemptTime). | High. |
| §1.4 FGS notification semantics | Modify `OfferListenerService` to compute "any tunnel needs me" predicate and post a paused notification + suspend the WSS read loop when the predicate is false. ~40 LOC. | High. |
| §2.1 automatic cascade | Already implemented in CASCADE-2; remove the global gate and add per-tunnel `relayPolicy`. | High; the hard part is done. |
| §2.3 default = Block / Ask-at-first-eligibility | Add `relayPolicy: Ask` to the `Tunnel` data class. Wire the banner on TunnelList rows. ~80 LOC plus persistence migration. | High. |
| §3.2 single-row Bridge presentation | Add `groupId: UUID?` to `Tunnel`. Migration is one nullable field (the pattern is established — see `Tunnel.kt:34-48` where `subnetV6`, `claimedRoutes`, `brokerWss` were all added the same way). Schema migration ~50 LOC plus tests; ViewModel grouping ~40 LOC; UI rendering ~30 LOC. | High. |
| §4 transition log + dropped-same-uid units | Ring buffer per tunnel: trivial. The dropped-same-uid counter is already in gvisor `Stats`; we surface it as packets (count, not bytes). | High. |
| §4 broker URL surfacing | Already in `Tunnel.brokerWss` (`Tunnel.kt:40`); just render. | High. |
| §4 gvisor route table dump | Needs a new JNI export (no current method dumps routes). Lowest-priority detail field; ships if cheap, otherwise dropped. | Medium; punt. |
| §5.1 three-tile first run + Tile #3 flow | Replaces `ui/OnboardingScreen.kt`'s three-page pager. 300-500 LOC plus the Bridge flow's two-step wizard. | High but larger than v1 claimed. |
| §6.1 specific port-conflict cause | `/proc/net/udp` readability lost at API 29. Will ship as "port in use" without naming the holder uid. | Low; concede. |
| §6.2 routing-loop ChromeOS deep-link | `Settings.ACTION_VPN_SETTINGS` exists; ARC honors it. No JNI work. ~30 LOC. | High. |
| §7 long-press "Bridge with…" menu | Compose `dropdownMenu` is standard; the compatibility predicate is the §2.1 rule. ~80 LOC. | High. |

### Things I claim are impossible

(Unchanged from v1 — the critic didn't push on these.)

- **Reading ChromeOS-native WG client config**: confirmed in the brief, confirmed
  by our own packet captures. We can warn the user passively (§6.2); we cannot
  read the config.
- **Per-joiner VpnService consent**: the brief locks this. UX consequence:
  consent is a one-shot per applicationId, and once granted, all joiners under
  that buildType inherit. We surface this honestly in onboarding.
- **Routing the wgrtc app's own traffic through its own joiner**: Android
  refuses; the brief is correct. UX consequence: `host_forwarder` traffic
  visibly skips the joiner. We document this in Detail under "Through:
  doesn't route through *Work VPN*" with a small info icon.

---

## 9. Open questions for the reviewer

(Some pruned from v1 — the critique resolved them.)

1. **The "Connection" rename.** Does collapsing host/joiner into one noun lose
   information that power users need? The diagnostic surface still exposes both
   words.
2. **§2.3 Ask-at-first-eligibility.** Three-button banner ("Allow once / Allow
   always / Block always"). Is three buttons too many? The alternative is a
   two-button "Allow / Block" plus a sticky-dismiss option, but I worry the
   sticky-dismiss meaning is unclear.
3. **§3.2 single-row Bridge vs. two rows.** `groupId` discriminator: do users
   prefer the collapsed view or always-two-rows? Cheap to A/B in debug builds.
4. **§5.1 Tile-#3 discoverability.** "Bridge two networks" — self-explanatory or
   does it need a sub-line? ("Share a remote VPN with devices on your local
   Wi-Fi.")
5. **State alphabet size.** Nine states now (added `Pairing`). Still too many?
   `Idle` is the suspicious one — the round-2 design gives it explicit exits,
   but does the *user* care about the Idle/Connected distinction or only the
   maintainer?
6. **Onboarding tile #2 "Share my network".** Most users *should never see this*
   because the use case is rare and the loop hazards are real. Should it be
   hidden behind a "More options" gesture?
7. **The `relay: never` policy.** Per-tunnel or per-(host, joiner) pair?
   Per-tunnel is in the round-2 design; per-pair is more precise but
   requires an N×M settings surface.
8. **Permanent-vs-recoverable failure classification.** `PeerKeyRejected` —
   permanent or recoverable? `ConsentSilentlyDenied` definitely permanent.
   The split is judgment; the transition log makes mistakes recoverable.

*(Cut from v1: §9.5 routing-loop probe latency — moot, no active probe;
§9.7 drag-to-bridge — cut entirely.)*

---

## 10. What this design deletes

For the reviewer to push back on, here's what we're proposing to *remove*:

- Global cascade toggle in Settings (`SettingsStore.kt:57-61`, `K_CASCADE_ENABLED`).
- "Host Mode" as a user-facing concept and the `HostModeSection` composable.
- Implicit ordering of joiners-then-hosts in TunnelList.
- The current single-state "active / inactive" boolean mutation pattern in
  `WgrtcViewModel`'s `_activeJoinerNTunnelIds`.
- Any UI string containing the words "joiner" or "host" outside the diagnostic fold.
- The current three-page onboarding pager (`ui/OnboardingScreen.kt`); replaced
  by the three-tile first run.
- §7's drag-to-bridge gesture (was: speculative; now: cut).

What we keep:

- The wormhole pairing flow (it's good and orthogonal). Now explicitly modeled
  via the `Pairing` state.
- The QR / paste / manual config paths (folded under Tile #1).
- The OfferListener foreground notification — but with the §1.4 semantics that
  let it stand down when no tunnel needs it.
- The Edit raw config escape hatch (under "technical details").

---

## 11. Implementation order (rough)

**Changed since v1:** N-host UX surfaced as step 9 per critic's loose end.

1. **Land the state machine + transition log** (incl. `Pairing`). Pure-Kotlin;
   pure-JVM testable. Don't change any UI yet. Subscribe diagnostic logging to
   it.
2. **Wire the three phantom-active signals** through the registry. Phantom-active
   failure dies.
3. **Remove the global cascade toggle.** Replace with per-tunnel `relayPolicy`
   defaulted to `Ask`. Wire §2.3's three-button banner.
4. **Repaint TunnelList rows.** Direction badges, status pills, no "host" word.
5. **Repaint TunnelDetail.** Transcript view, broker URL surfaced,
   §4.1 specific failure messages including `BrokerMissing` and `ConsentSilentlyDenied`.
6. **Three-tile first run.** Tile #3 is the headline.
7. **§6.2 passive ChromeOS dialog** + deep-link.
8. **`groupId` schema migration** + single-row Bridge presentation + long-press
   "Bridge with…" menu.
9. **N concurrent host tunnels UX.** The current code already supports
   multiple host bridges (`CascadeWiring` keys host bridges by handle); UX
   needs: per-host listen-port selection in Tile #2 with a "next available port"
   default (avoid 51820 collision); naming defaults so two "Home Hosts" don't
   look identical; per-host `relayPolicy`. The §2.3 banner already enumerates
   joiners; same enumeration applies host-side.

Each step is independently shippable. Steps 1–2 alone resolve the most painful
brief items.

---

## 12. Schema migration plan

**New in v2.** v1's §11 step 8 understated this.

The serialized `Tunnel` schema (`data/Tunnel.kt`) is `kotlinx.serialization` JSON
with `encodeDefaults = true` (per the memory note about the silent-drop bug). The
nullable-add-with-default pattern is established — `subnetV6`, `claimedRoutes`,
`brokerWss` all landed that way.

Round-2 adds to `Tunnel`:

```kotlin
val groupId: String? = null,                            // paired-Bridge UUID
val relayPolicy: RelayPolicy = RelayPolicy.Ask,         // host tunnels only
val intent: TunnelIntent = TunnelIntent.NoIntentYet,    // last switch position
```

Plus `OfferListenerService.lastActiveSet: Set<String>` for the §1.4 Resume hint.

Migration: all four fields default-deserialise cleanly from pre-v2 `tunnels.json`.
Old tunnels get `groupId=null`, `relayPolicy=Ask`, `intent=NoIntentYet` (which the
UI maps to "switch off, never asked-for", same as freshly-imported). On next save,
the encoder writes the new fields out. No version bump; no destructive migration.

Removal: `SettingsStore.K_CASCADE_ENABLED` is deleted. `resetToDefaults()` no
longer touches it; old prefs values are ignored. Migration test verifies that a
user with cascade ON pre-v2 sees `Ask` (not `Always`) on every host tunnel
post-v2 — no automatic cascade fires until the banner is confirmed.

---

## 13. Rollback plan

**New in v2.** Critic asked: "What happens when CASCADE-2 itself is buggy?
The OFF-by-default toggle is the escape hatch you're removing."

Three layers of recourse if a CASCADE-2 regression ships:

1. **User-side**: per-tunnel `relayPolicy: Never` in detail screen. Tearing
   down cascade routes is already supported via `UnregisterHostBridge`. Same
   affordance v1 exposed; round-2 makes it the explicit kill-switch.
2. **App-side hotfix**: flip the default `relayPolicy` from `Ask` to `Never`
   for newly-imported tunnels. Existing user `Always` choices are preserved.
   Hotfix LOC: ~5 in the data-class constructor; no schema change.
3. **Emergency kill-switch**: a hidden `K_CASCADE_FORCED_OFF` flag in
   `SettingsStore`, defaulted false, settable only via adb broadcast on
   `.debug` / `.agent` builds. Short-circuits every cascade evaluation to
   "blocked". The regression equivalent of the v1 global toggle, but it lives
   in the diagnostic surface, not the user surface.

The argument for removing v1's toggle isn't "no escape hatch exists" — it's
"the escape hatch shouldn't be the primary UX".

---

*End of v2. The transition log is the highest-payoff item; if everything else
is rejected, ship that and §6.1's three-signal phantom-active fix.*
