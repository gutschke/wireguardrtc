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

## Round-3 amendments (applied 2026-05-17)

The round-2 critic returned **ship-with-amendments** with three must-fixes
(A1, A2, A4) and two questions for the maintainer.  Both questions are
answered in-doc:

**Q1: Is `OfferListenerService` allowed to call `VpnService.prepare()`?**
**Yes** — for detection.  A `Service` cannot launch the consent UI (an
`Activity` startActivityForResult is required), but `prepare()` itself is a
static call that returns either `null` (consent granted) or an `Intent`
(consent missing).  We only need the latter signal; we don't try to launch
the Intent from the service.  See §1.2 row 4 (new) and §6.1 step 4 (new).

**Q2: `relayPolicy` per-host or per-(host, joiner)?**  **Per-host.**  Matches
the §2 prose and §9.7's earlier answer.  §2.4's re-prompt-per-new-joiner
clause is removed; one decision applies to the host tunnel and persists
across joiner appearances.  Users wanting per-pair granularity split into
two host tunnels with disjoint enrolled-peer sets.

**Must-fixes applied**:

- **A1** (§1.2 row 4 + §6.1 step 4): periodic `OfferListenerService`
  re-`prepare()` via WorkManager catches the phantom-active window for users
  who never re-foreground the app.
- **A2** (§12): `TunnelIntent` enumerated as `NoIntentYet | WantsOn |
  ExplicitlyOff`; preserves `Disabled` vs. `Paused (user)` across reboot.
- **A4** (§2.4): re-prompt-per-new-joiner clause dropped; one policy
  per-host.

**Should-fixes** (A3, A5) noted as follow-up:

- **A3** — `Pairing` failure split: SAS-mismatch/timeout → `Failed
  (recoverable)`; user-cancel / code-expired → `Failed (permanent)`.  Will
  land with the §11.1 implementation work.
- **A5** — `K_CASCADE_FORCED_OFF` hidden Settings long-press for release
  builds.  Will land with the §11.3 (`relayPolicy`) implementation work.

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
| `OfferListenerService` low-cadence re-`VpnService.prepare()` | new — WorkManager `PeriodicWorkRequest` @ 30 min, gated on ≥ 1 joiner with `intent=WantsOn` | A `Service` may call `VpnService.prepare()` to **detect** consent loss (it can't launch the consent UI — that's Activity-only — but a non-null-Intent return value is the signal we need). Catches the phantom-active scenario where the user never re-foregrounds the app for hours/days. Skipped when no joiner intends to be on. |
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

**Invariant 1: ViewModel downstream of service, never upstream.** Today,
`_activeJoinerNTunnelIds` is a `MutableStateFlow` mutated by the UI on Connect
*and* read by the UI to draw the row. When the system revokes consent the
service dies but the flow doesn't update. Inverted: the service owns a
`TunnelStateRegistry` (process-wide, rebuilt from UAPI on service start) and
the ViewModel **only reads**. Connect posts a command; service mutates the
registry; registry emits; UI redraws.

**Invariant 2: state is derived, not stored.** `Connected = lastHandshakeTime
> now - 180s AND service.bridgeAlive(id) AND !consentRevoked(id)`. Emission
cadence is 1 s (`WgrtcViewModel.kt:1868`); worst-case freshness ~1 s. No
attempt to make derivation packet-synchronous.

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
revisit Settings on every new tunnel. Three costs paid every install; benefit
zero in the simple-joiner majority. The critic conceded this in Win #1.

Replaced by per-tunnel `relayPolicy: Always | Never | Ask`, stored on the host
tunnel (the side that admits cascade traffic, per §2.1).

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
and *Lab Cluster*." A single decision applies to the host tunnel and persists
**per-host** (not per-(host, joiner) pair).  A future joiner that overlaps the
same host's address space is admitted under the same policy without
re-prompting — Allow means "allow this host to relay to any joiner that
covers a destination it admits", Block means "never relay this host".  See
§9.7: this resolves the round-2 critic's A4 (the v2 draft accidentally
modelled both per-host and per-pair semantics).  Per-pair granularity (an
N×M settings surface) is out of scope; users who want it can split into two
host tunnels with disjoint enrolled-peer sets.

---

## 3. TunnelList: the row is a Connection

### 3.1 Reframing: kill "host" and "joiner" as user-facing words

**Changed since v1:** the switch and `Paused (user)` reconciled — exactly
**one** pause-with-intent control (the switch).

Show **Connections**. A Connection has:

- a **name** (user-given or imported).
- a **direction badge** (icon, not text): inbound arrow = host, outbound
  arrow = joiner, two arrows = bridge.
- a **status pill** from §1's alphabet, color-coded (green Connected, gray
  Idle, amber Degraded/Paused-system, blue Paused-user, red
  Failed-recoverable, dark red Failed-permanent, neutral Disabled,
  violet Pairing).
- a **right-side switch** bound to user intent. If live state is
  Paused-system, switch shows on but pill shows the system pause. Flipping
  off in Paused-system writes `intent=off` (Resume notification no longer
  prompts on reboot).
- **Tap the row** = navigate to detail. Tap is never a state change.

Resolves the critique's "two pause-with-intent semantics on two controls".

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
4. **`OfferListenerService` periodic re-`prepare()`** (round-2 amendment A1).
   A WorkManager `PeriodicWorkRequest` @ 30 min cadence, gated on at least one
   joiner having `intent=WantsOn`. Same detection as (3) but reaches the
   never-re-foregrounding user — the dominant phantom-active cohort. The
   service can't launch the consent Intent (that's Activity-only), but the
   non-null return value of `prepare()` is itself the signal we need. Emits
   `RevokeEvent(BACKGROUND_RESYNC)`.

**Implementation cost (honest)**: ~150-220 LOC after A1's WorkManager addition.
Split across the two services (~40), `MainActivity` (~30), a new
`TunnelStateRegistry` (~80), WorkManager hook (~20), and the ViewModel
subscription rewrite (~30), plus tests at each layer. The v1 estimate was
wrong; v2's was light by ~20-40 LOC.

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

**Cut since v1.** The drag-to-bridge gesture is removed — joiner↔joiner
composition has no implementation (cascade is host→joiner), and the
phone-class drag affordance was already weak (v1 §9.7 admitted it).

Replacement: a long-press menu item on each row, **"Bridge with…"**, opening
a single-select list of compatible tunnels. Compatibility = the §2.1 rule
applied symbolically (host shows joiners covering at least one of its
enrolled-peer destinations; joiner shows hosts). Selecting writes a shared
`groupId`, optionally renames to `Source ↔ Sink`, and the §2.3 banner fires
at next eligibility.

---

## 8. Feasibility check

**Changed since v1:** honest LOC for §6.1; §6.2 dropped from Medium to Low
(no JNI); §3.2 groupId no longer "minor"; §5.1 onboarding cost surfaced.

| Claim | Engineering | Confidence |
|---|---|---|
| §1.2 phantom-active fix (3 signals) | ~120-180 LOC across services + Activity + new registry + ViewModel | High |
| §1.3 derived state @ 1 s | Poll exists; add `HANDSHAKE_STALE_SEC = 180` (`RejectAfterTime`) | High |
| §1.4 FGS suspend-when-all-paused | ~40 LOC in OfferListenerService | High |
| §2.1 automatic cascade | CASCADE-2 already implements; remove global gate, add per-tunnel `relayPolicy` | High |
| §2.3 `Ask`-at-first-eligibility | Add `relayPolicy` to `Tunnel`; wire banner on rows. ~80 LOC + migration | High |
| §3.2 single-row Bridge + groupId | Add `groupId: UUID?` (pattern established in `Tunnel.kt:34-48`). ~50 LOC schema + ~70 LOC UI | High |
| §4 transition log + counters | Ring buffer trivial; gvisor stats already exist (surface as packet count) | High |
| §4 broker URL surface | Already in `Tunnel.brokerWss` (`Tunnel.kt:40`); just render | High |
| §4 gvisor route table dump | New JNI export needed (no method dumps routes today). Punt. | Medium |
| §5.1 three-tile first run + Tile #3 | Replaces `OnboardingScreen.kt`'s 3-page pager. 300-500 LOC + wizard | High |
| §6.1 port-conflict holder uid | `/proc/net/udp` gated at API 29; ship as "port in use" only | Low — concede |
| §6.2 ChromeOS deep-link | `Settings.ACTION_VPN_SETTINGS` exists, ~30 LOC | High |
| §7 long-press "Bridge with…" | Compose dropdown, ~80 LOC | High |

### Things I claim are impossible

Unchanged from v1 — critic didn't push:

- Reading ChromeOS-native WG client config (warn passively only — §6.2).
- Per-joiner VpnService consent (locked by the brief; consent is one-shot per
  applicationId).
- Routing wgrtc's own traffic through its own joiner (Android refuses;
  `host_forwarder` visibly skips the joiner — documented in detail).

---

## 9. Open questions for the reviewer

Pruned from v1 — several resolved by the critique.

1. **The "Connection" rename.** Does collapsing host/joiner lose info power
   users need? Diagnostic surface still exposes both words.
2. **§2.3 three-button banner.** Too many choices? Alternative: two buttons
   plus sticky-dismiss, but the dismiss meaning is unclear.
3. **§3.2 single-row vs. two rows.** A/B-able in debug builds.
4. **§5.1 Tile-#3 title.** "Bridge two networks" self-explanatory, or
   needs a sub-line?
5. **State alphabet size.** Nine. `Idle` is the suspicious one — round-2
   gives it explicit exits, but does the *user* care about the Idle/Connected
   distinction or only the maintainer?
6. **Onboarding tile #2 "Share my network".** Should it be hidden behind
   "More options"? The use case is rare; loop hazards are real.
7. **`relay: never` policy.** Per-tunnel (current design) or per-(host, joiner)
   pair? Per-pair is more precise; per-tunnel is easier to reason about.
8. **Permanent vs. recoverable classification.** `PeerKeyRejected` — which?
   `ConsentSilentlyDenied` is definitely permanent. Judgment call; the
   transition log makes mistakes recoverable.

*(v1's §9.5 routing-loop probe latency and §9.7 drag gesture are moot.)*

---

## 10. What this design deletes

Removed:
- Global cascade toggle in Settings (`SettingsStore.kt:57-61`, `K_CASCADE_ENABLED`).
- "Host Mode" as a user-facing concept; the `HostModeSection` composable.
- Implicit joiners-on-top ordering.
- UI-side mutation of `_activeJoinerNTunnelIds` in `WgrtcViewModel`.
- "joiner" / "host" strings outside the diagnostic fold.
- The three-page `OnboardingScreen.kt` pager — replaced by three tiles.
- §7's drag-to-bridge (cut, not iterated).

Kept:
- Wormhole pairing flow (now explicitly modeled via `Pairing` state).
- QR / paste / manual config paths (under Tile #1).
- OfferListener FGS notification (with §1.4 stand-down semantics).
- "Edit raw config" escape hatch.

---

## 11. Implementation order (rough)

**Changed since v1:** N-host UX added as step 9 per critic's loose end.

1. State machine + transition log (incl. `Pairing`). Pure-Kotlin, pure-JVM
   testable. No UI change yet.
2. Wire the three §6.1 phantom-active signals through the registry.
3. Remove the global cascade toggle; add per-tunnel `relayPolicy` defaulted to
   `Ask`; wire §2.3 banner.
4. Repaint TunnelList rows (direction badges, status pills, no "host" word).
5. Repaint TunnelDetail (transcript view, broker URL, §4.1 causes including
   `BrokerMissing` and `ConsentSilentlyDenied`).
6. Three-tile first run; Tile #3 headline.
7. §6.2 passive ChromeOS dialog + deep-link.
8. `groupId` schema migration; single-row Bridge presentation; long-press
   "Bridge with…" menu.
9. **N concurrent host tunnels UX.** Backend already supports it
   (`CascadeWiring` keys hosts by handle). UX needs: per-host listen-port
   selection in Tile #2 with "next available port" default (avoid 51820
   collision); name disambiguation so two "Home Hosts" don't render
   identical; per-host `relayPolicy`. The §2.3 banner enumeration generalises
   host-side.

Each step is independently shippable. Steps 1–2 alone resolve the painful
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

with these enum shapes (amendment A2 — values explicit so `Disabled` vs.
`Paused (user)` survives serialisation):

```kotlin
enum class RelayPolicy { Ask, Always, Never }

enum class TunnelIntent {
    /** Never asked-for.  Freshly-imported / pre-migration tunnels land
     *  here.  Maps to `Disabled` in the state machine — switch off,
     *  status pill "Disabled". */
    NoIntentYet,

    /** User flipped the switch on.  Maps to whichever live state the
     *  signal stack derives (Arming / Connecting / Connected / Idle /
     *  Degraded / Paused (system) / Failed (recoverable | permanent)). */
    WantsOn,

    /** User flipped the switch off after having it on (or after a
     *  Paused (system) transition).  Maps to `Paused (user)`.  Sticky
     *  across reboots; survives upgrades.  Distinct from
     *  `NoIntentYet` so we don't auto-resume a tunnel the user has
     *  explicitly paused. */
    ExplicitlyOff,
}
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
