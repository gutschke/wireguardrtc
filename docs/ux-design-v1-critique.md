# Critique of ux-design-v1.md — Round 1

## 1. The thesis

**The design's central claim**: every UX pain point reduces to "the ViewModel
disagrees with reality", and a single authoritative `StateFlow<TunnelState>` per
tunnel, fed by every observable signal, will collapse the symptoms.

**Defensible?** The reactive-state-machine half is yes. The "Connections, not
Tunnels" reframing is *not* — it conflates a presentation-layer rename with the
state-machine work and uses the latter to smuggle the former past review. Worse,
two of the load-bearing signals (`vpnService.onRevoke()`, `nativeBridge.deviceReady()`)
either don't reliably fire or don't exist on the JNI surface today, and the
designer hasn't checked. There is no fatal flaw — round 2 can ship if the doc
narrows its scope — but **§7 ("drag-to-bridge") and the §2.3 banner system are
solving non-problems and should be cut, not iterated on**.

---

## 2. Top 5 attacks

### Attack 1 — `onRevoke()` is not the callback you think it is

**Claim**: §1.2 "vpnService.onRevoke() … All joiners → Paused (system). ViewModel
observes a `MutableSharedFlow<RevokeEvent>` that the service emits before
`stopSelf()`." §8 calls this "High; ~30 lines."

**Failure mode**: Android's `VpnService.onRevoke()` fires when **another VPN app
takes over** (the system replaces the active VPN service). It does **not** fire
for "the user toggled VPN permission off in Settings → Apps → wgrtc → Permissions",
because that path kills the process via `force-stop` semantics — your service
gets `onDestroy()` without a clean callback, or the process is reaped outright
and the new instance restarts into a state where `VpnService.prepare()` returns
non-null again. The phantom-active failure (use case G) the design says it
"fixes structurally" is more likely the *force-stop* variant than the
*another-VPN-takes-over* variant. The proposed `SharedFlow<RevokeEvent>` will
silently never emit in the common case.

Verified by reading `service/JoinerVpnService.kt:108-110`: today the code only
detects revocation via `builder.establish()` returning null on the *next* connect
attempt. That's the only signal the project has ever relied on, and the design
proposes replacing it with a callback that has worse coverage.

**Severity**: 5. This is the headline phantom-active fix; if the callback
doesn't fire in the dominant scenario, §6.1's "Implementation cost: ~30 lines
of Kotlin" is fiction.

**Fix**: structural. Either (a) add a periodic re-`prepare()` check on every
foreground transition, or (b) wire `Process.myPid()` death detection via a
sticky JobIntentService, or (c) accept that the existing "null pfd on next
attempt" signal is the floor and write the doc against it. Option (c) is the
honest one.

### Attack 2 — Cascade auto-install rule contradicts the CASCADE-2 implementation

**Claim**: §2.1 rule (2): "H has AllowedIPs P_H and J has AllowedIPs P_J such
that some peer on H has AllowedIPs that *exclude* a subnet in P_J — i.e., the
H-side peer wants to reach addresses that only J can deliver."

**Failure mode**: The actual CASCADE-2 wiring (`data/CascadeWiring.kt`, `docs/cascade-n-design.md:22`)
is **one-directional**: "host tunnels that want to egress via a joiner." Host →
joiner. The design talks as if address-space overlap were symmetric. It isn't.
A joiner-mode tunnel can't relay traffic *into* a host's enrolled peer set
without a substantial second piece of infrastructure (the joiner-side peers
would have to address the host's enrolled peers' /32s — which they don't, because
the joiner-side server doesn't advertise those routes). The "Devices on *Home*
can now reach *Work VPN*" banner in §2.3 is doing the correct direction — but
§2.1's rule (2) phrasing reads as if J → H were the trigger.

Re-read §2.1 carefully: "some peer on H has AllowedIPs that *exclude* a subnet
in P_J" — this is unparseable. P_H's peers are individual enrolled-peer /32s on
the host's subnet. They have no relationship to P_J. The cascade rule is "H has
an enrolled peer whose traffic would route into P_J", i.e., the cascade gets
installed when *traffic emerging from H's gvisor netstack* has a destination
covered by *J's AllowedIPs*. That isn't what the prose says.

**Severity**: 4. The doc as written describes a feature that the code can't
implement and that nobody asked for.

**Fix**: tweak the doc. Rewrite §2.1 against the actual asymmetric H → J cascade
and say so explicitly. The asymmetry also kills the "drag joiner onto joiner to
bridge" gesture in §7 — there is no such gesture.

### Attack 3 — The state alphabet's `Idle` state has no defined exit

**Claim**: §1.1 row 5: "Idle — Connected-by-config but no recent handshake
(joiner with no traffic and no keepalive; not a fault)."

**Failure mode**: WireGuard handshakes don't refresh on idle. A joiner with
`PersistentKeepalive = 25` will hold `Connected`. A joiner *without*
PersistentKeepalive will pass `lastHandshakeTime > now - 180s` for the first
180s, then drop to `Idle` forever, with **no way back to `Connected` short of a
new user-initiated packet**. The transition table in §1.2 says "Connecting →
Connected on first non-zero handshake; Connected → Idle after `HANDSHAKE_STALE_SEC = 180`",
but does not show **Idle → Connected**. If the user has been on Idle for an hour
and now opens an SSH session, what state does the UI display while the new
handshake is in flight? The transition log will say "Connected → Idle (no
traffic) → ???".

There's also a related miss: `Connecting` is defined as "preconditions satisfied;
handshake in flight." But after Idle, when a new packet triggers a handshake,
there are no fresh preconditions to gather — should the state go straight to a
new `Connecting`? Or stay `Idle` until the first handshake completes? The doc
says nothing.

Also: the design says "180s matches WG RekeyAttemptTime semantics". This is
**wrong**. RekeyAttemptTime is 90s. RekeyAfterTime is 120s. RejectAfterTime is
180s. The number 180 is the *rejection* horizon, not the rekey horizon. Citing
the wrong WG constant in a state-machine spec is the kind of detail that
mis-leads downstream readers into believing the state design is grounded in
the wire spec.

Compounding: the current code already polls throughput on a **1-second** cadence
(`WgrtcViewModel.kt:1868`), not the 5-second cadence the design asserts in §1.2.
This is a small fact but a sloppy one — the designer didn't open the file before
citing the cadence.

**Severity**: 4. Without a defined Idle → {Connecting,Connected} transition,
every joiner without PersistentKeepalive will be permanently "Idle" in the UI
after 3 minutes, regardless of what's actually happening.

**Fix**: tweak the doc. Add Idle → Connecting on any of {tx packet observed,
endpoint reconfigure, user-initiated probe}. Also delete the wrong WG-constant
attribution.

### Attack 4 — The routing-loop probe (§6.2) needs inbound reachability the design admits we don't have

**Claim**: §6.2 step 2: "From an OS socket *outside* the netstack (real-Android
scope), send a magic UDP datagram to our own public IP on `listen_port`."

**Failure mode**: This requires the device to know its **public** IP and to
have an **inbound-reachable** path to itself. The footnote ("If the probe is not
feasible on a given device (no inbound port, CGNAT), we fall back to a softer
warning") is doing enormous load-bearing work. Inbound reachability is the
exact thing host-mode-on-mobile rarely has — that's why this whole project
exists. The success path of the probe (host has a public IP, has a routable
inbound port) describes the *minority* of devices.

Worse, "tag arrival in gvisor by which `channel.Endpoint` delivered it" — there
is no JNI surface today that exposes per-NIC delivery tags to Kotlin. Adding it
is a multi-file change in `wgbridge_native/` plus a JNI binding. The §8 row
classifies this as "Medium" but the LOC estimate is implicit zero; in practice
it is the most expensive feasibility item on the list.

And the routing-loop scenario the probe is supposed to catch (use case D, the
ChromeOS-native WG client routing through our own joiner) **only happens when
the user has a host tunnel** *and* a ChromeOS WG client *and* the WG client's
AllowedIPs covers our outer transport. On the cohort that hits this bug, the
probe usually can't run. The diagnostic is least useful for the population that
needs it.

**Severity**: 3. The probe is partially useful but the doc oversells it. The
"impossible" claim in the brief was closer to right than the design's "possible
because we control both endpoints" rebuttal.

**Fix**: structural. Replace the probe with a *passive* check: at Arming time,
ask the user "do you have another WireGuard client active on this device with a
route to a public address?" via a yes/no. If the user is on ARC, deep-link to
ChromeOS Settings. Treat the loop diagnosis as a soft warning, not an
authoritative gate.

### Attack 5 — The §2.3 default-Block-on-full-tunnel heuristic doesn't match real configs

**Claim**: §2.3: "Default is **Block** for full-tunnel joiners (AllowedIPs covers
a default route) and **Allow** otherwise."

**Failure mode**: The most common AllowedIPs values in real-world deployments
are split-tunnel `10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12` (the RFC1918
trio), which the heuristic classifies as Allow-by-default. That's the corporate
WAN case the §9.2 open question worries about: a sibling visiting the user's
"Home" host tunnel will, by default, gain the right to egress through the
user's "Work" joiner to a corporate `10.0.0.0/8`. The heuristic exists to
prevent exactly this, but the chosen rule misses it.

Also: an enterprise joiner whose AllowedIPs is the *literal* corporate ranges
will not match `0.0.0.0/0` — and the user has no global "this connection is
sensitive" tag to flip the bit. The relay-policy default is heuristic in a
domain (network privacy) where heuristic defaults bite.

**Severity**: 3 — high if the user shares their phone or sets up a guest host.

**Fix**: tweak the doc. Make the default *always* Block; require explicit
opt-in for cross-tunnel relaying. The §2.3 banner is the discovery surface.
This is the opposite of the current §2.3 default, but it matches the privacy
expectation.

---

## 3. Feasibility audit (line-by-line against §8)

| Row | Verdict | Evidence |
|---|---|---|
| §1.2 onRevoke wired to ViewModel | **False — Low confidence** | `service/JoinerVpnService.kt:108-110`, `service/JoinerNVpnService.kt:154-157`: no `onRevoke()` override exists today and the *Android* `onRevoke()` semantics don't cover Settings-revocation. See Attack 1. |
| §1.3 derived state from `lastHandshakeTime` | **True but cadence wrong** | `WgrtcViewModel.kt:1868` polls at 1s, not 5s. Stale-threshold `180s` cited against the wrong WG constant. See Attack 3. |
| §2.1 automatic cascade | **True but defaults wrong** | `data/SettingsStore.kt:57-61`: `cascadeEnabled` defaults to **false** until field validation. The design says "the hard part is done" — true mechanically; not true that removing the gate is uncontroversial. The toggle is also literally the only knob preventing accidental relay on devices where CASCADE-2 has known regressions. |
| §2.3 default-Block for `0.0.0.0/0` | **True, but the heuristic is too narrow** | See Attack 5. |
| §3.2 single-row Bridge presentation | **True; schema cost understated** | `data/Tunnel.kt:34-48`: no `groupId` exists. Adding it is a `.serialization` migration; the existing pattern in this file shows three other "added in V6.2" / "added in V6.3" fields, so the discipline exists. ~50 lines, not the "minor" the doc claims. |
| §4 transition log | **True; performance flag** | A ring buffer per tunnel is trivial, but the §4 detail screen also wants "the gvisor route table for this tunnel" and "dropped invalid-pubkey" — neither has a JNI surface today. `data/WgBridgeNative.kt` exposes 6 JNI methods, none of them gvisor-route-table dumps. |
| §5.1 Tile-#3 "Bridge two networks" flow | **True but slow** | The existing onboarding (`ui/OnboardingScreen.kt:62`) is a three-page tour, not a three-tile launcher. The design proposes replacing the entire onboarding shape — bigger change than "pure UI". |
| §6.2 routing-loop probe | **Mostly false** | See Attack 4. JNI surface doesn't exist; success path is the rare one. |
| §6.1 port-conflict cause naming | **Doc concedes Low** | Correct concession. Worth noting that since API 29, even reading `/proc/net/udp` is gated; the design's "API 28" line is correct. |
| §7 drag-to-bridge | **Wrong premise** | See Attack 2 — cascade is asymmetric. Dragging a joiner on top of another joiner cannot compose them into a bridge because joiner→joiner cascade doesn't exist. The gesture only meaningfully composes a host with a joiner, in that order. The doc doesn't notice. |

### Hidden-assumption ledger

- **"Bonjour discovery"** (§5.1 tile #1 bullet 4). There is no NSD / mDNS code
  in the project (`grep -r NsdManager` returns nothing in `app/src/main/`).
  This is a fresh feature, not a fold-under-Tile-1.
- **"three single-line facts"** in §4 includes "Through: cellular / Wi-Fi". The
  underlying transport is the *selected egress*, not the active NetworkCallback
  default. `data/NetworkChangeMonitor.kt:44-82` tracks both `filtered` and
  `default` callbacks; the design assumes only one of them suffices.
- **"deep-link to ChromeOS settings if ARC"** in §4.1 — no ARC-specific intent
  detector exists today.

---

## 4. State-model dissection

Walking the §1.1 alphabet:

- **Disabled**: only entry is "user has the tunnel saved". Missing: what state
  does a freshly-imported tunnel start in? The doc implies Disabled — but the
  Connect button in §3.1 toggles to "whatever the user last asked for". A
  tunnel that was *never* asked-for has no last-ask; the toggle binding is
  undefined.
- **Arming**: includes "consent grant". Race: if the consent dialog is open and
  the user backgrounds the app, what state? `MainActivity.kt:485-491` shows
  consent flow lives in the Activity scope; the registry the design proposes
  is process-scope. The Arming state has no "consent pending in foreground"
  vs. "consent pending in background" distinction. The activity can die.
- **Connecting**: trigger is `nativeBridge.deviceReady()`. **The JNI does not
  expose this callback.** `WgBridgeNative.kt` lines 158-247: 6 external methods,
  none of them is a Kotlin-observable "device ready" up-call. The Arming →
  Connecting transition needs new Go-side infrastructure.
- **Connected**: derived; race: `lastHandshakeTime` poll runs at 1s; if a
  handshake lands and is immediately invalidated (peer pubkey changes), the
  UI shows Connected for ≤1s. Acceptable, but the §1.3 invariant says state
  is "derived on next emission" — it isn't, it's emission-latency-bounded.
- **Idle**: see Attack 3 — no defined exit transition.
- **Degraded**: triggers say "Idle → Degraded on user-initiated traffic that
  fails." The system can't observe "user-initiated traffic"; it observes
  tx packets. App-uid skipped traffic (host_forwarder's own probes,
  `data/HostModeBackend.kt:323-328`) will look identical. Ambiguous signal.
- **Paused (system)**: see Attack 1.
- **Paused (user)**: "user tapped the same row twice; sticky across reboots."
  Today the row is the Connect/Disconnect button; double-tap means
  Connect-then-Disconnect, which is what most users expect. Re-interpreting
  it as Pause-with-intent silently changes the meaning of a touch they've
  done before. Conflict with §3.1's "right-side switch toggles between
  Disabled and (whatever the user last asked for)" — those are two different
  pause semantics on two different controls.
- **Failed (recoverable)**: "the next network event re-arms." On a stable
  Wi-Fi with a peer who's just gone offline, there is **no network event**.
  This state is a black hole until the user re-taps.
- **Failed (permanent)**: see §9.10 — the doc itself flags that the
  recoverable/permanent split is brittle.

---

## 5. UX hostile-user test

### Scenario A — The deleted broker

User on a fresh install pastes a `wgrtc://` URI from a colleague, gets an
ENROLL tunnel. Goes to Settings, taps "Reset broker to defaults" (a button that
exists today, `SettingsStore.kt:163-164`). Then deletes the broker URL by
hand. The OfferListenerService keeps trying to reconnect to an empty WSS
endpoint; the design's state machine has no `Failed.BrokerMissing` cause.

The transition log fills with `Connecting → Failed (recoverable)` retries, and
the user has no UI to ask "where's my broker?" — the §4 "Show technical details"
fold contains the *current* endpoint, not the broker URL. The §4.1 `FailureCause`
table doesn't include this case at all.

**Multiple-failure variant**: user has *also* uninstalled the colleague's
host-side daemon. Now even with a correct broker, no OFFER comes through. The
state is stuck in `Connecting` with no failure transition.

### Scenario B — Two configs sharing a /8

User imports a `10.0.0.0/8` joiner (corporate WAN) and a `10.99.0.0/24`
host-mode tunnel for a friend. `TunnelOverlapGuard` lets this through because
`10.99.0.0/24` is LPM-resolvable inside `10.0.0.0/8`
(`data/TunnelOverlapGuard.kt:21`).

Per §2.1 rule (2), the joiner's `10.0.0.0/8` covers traffic destined for the
host's enrolled peers at `10.99.0.0/24`. The §2.3 default is "Allow" because
`10.0.0.0/8` ≠ `0.0.0.0/0`. The user's friend now egresses through the user's
corporate WAN by default. This is **the privacy-leak the §2.3 banner is
supposed to prevent**, and the heuristic misses it.

### Scenario C — Captive portal + host mode + Force-Stop mid-Bridge

User sets up a "Bridge two networks" (§5.1 tile #3). The shared `groupId`
spawns one host tunnel and one joiner. They board a hotel Wi-Fi with a captive
portal. The joiner's UDP socket succeeds (the portal hasn't intercepted it
yet), the host's UDP listen also succeeds. The state machine: both
`Connecting`, neither makes handshake progress, both fall to
`Failed (recoverable)`.

The user (annoyed) opens Settings → Apps → wgrtc → Force-Stop. The §1.3
"derived state" invariant collapses immediately: the process dies, the
service dies, the registry dies. On next launch the registry rebuilds from
UAPI — but UAPI is gone too. The state alphabet has no entry for "the user
killed us"; the row probably renders as `Disabled`, losing the "the user
asked for both halves of the bridge" intent.

The §3.2 `groupId` discriminator survives in storage. The §1.3 derived-state
machine cannot reconstruct that the user's intent was Connect. The two rows
re-collapse to one Bridge row that shows `Disabled` — which is wrong; the
user *did* ask for it.

---

## 6. Where the design wins

### Win 1 — Killing the global cascade toggle is right

§2.2's analysis is correct: a global Settings toggle is the wrong shape for a
property that's semantically per-tunnel. Even the current code's default-OFF
posture (`SettingsStore.kt:60`) is a workaround for not having per-tunnel
policy; the toggle exists because there's no place to put the per-tunnel
flag. Replacing the toggle with `relayPolicy: Always | Never | Ask` on the
Tunnel data class is a clean structural improvement — and is the smallest,
highest-payoff item on the §11 implementation order.

### Win 2 — The transition log as the primary diagnostic surface

§4's "transition log is the diff between what happened and what the user
expected" is exactly right. Today the only diagnostic surface is logcat, and
the only people who can read it are the maintainer over a screen-share.
Surfacing a structured ring buffer of state transitions per tunnel makes the
distance-to-diagnosis go from a 20-minute Zoom call to a copy-paste. This is
worth shipping even if every other item in the doc is rejected.

---

## 7. Recommendations for round 2

1. **(Must-fix)** Rewrite §1.2's `onRevoke` row. The Android callback doesn't
   cover the dominant phantom-active scenario. Acknowledge that the existing
   "null pfd on next establish" signal is the ground truth and design around
   it. Add a foreground-resume re-`prepare()` check.
2. **(Must-fix)** Add **Idle → Connecting** to the §1.2 table. Pick a signal
   (tx packet observed; endpoint reconfigure; user reopens detail screen) and
   write it down. As-stands, Idle is a terminal state for keepalive-less
   tunnels.
3. **(Must-fix)** Rewrite §2.1's rule (2). The cascade is one-directional
   (host → joiner). The current prose is unparseable and the implementation
   can't honor it as written.
4. **(Must-fix)** Flip §2.3's default to **Block** unconditionally. The
   `0.0.0.0/0`-only heuristic misses the RFC1918-trio enterprise joiner, which
   is the case the banner exists to catch.
5. **(Must-fix)** Either delete §6.2's routing-loop probe or rewrite it as a
   passive yes/no with deep-link to ChromeOS settings. The active probe needs
   a JNI surface that doesn't exist and inbound reachability we usually lack.
6. **(Should-fix)** Cut §7's drag-to-bridge entirely. It's a gesture that
   doesn't match the asymmetric cascade and the §9.7 open question already
   admits it's questionable. The long-press menu is sufficient.
7. **(Should-fix)** Reconcile §3.1's "switch is bound to user intent" with
   §1.1's "Paused (user)". You have two pause-with-intent semantics on two
   different controls; pick one.
8. **(Should-fix)** Specify what state a freshly-imported tunnel starts in.
9. **(Should-fix)** Add a `FailureCause.BrokerMissing` and surface the broker
   URL in §4's "technical details" fold.
10. **(Should-fix)** Correct the wrong WG-constant attribution ("RekeyAttemptTime")
    in §1.2.
11. **(Should-fix)** Correct the cadence claim — throughput polls at 1s
    today, not 5s.
12. **(Nice-to-have)** §5.1 Tile #1 says "discover via Bonjour" — either
    commit to building NSD/mDNS discovery (separate spec) or drop the bullet.
    Don't ship the tile pretending the path exists.
13. **(Nice-to-have)** Make §4.1's `FailureCause` enum's `humanMessage`
    field localizable. The doc treats them as strings today.

---

## 8. Loose ends

- **What happens to the OfferListenerService FGS notification while a tunnel
  is in `Paused (user)`?** The design says the §10 "OfferListener foreground
  notification" stays — but the notification's reason for existing is to keep
  the WSS alive for *connected* tunnels. If every tunnel is paused, the FGS
  is keeping a no-op socket alive.
- **The `groupId` migration path.** §11 step 8 says "schema migration" but
  doesn't address: what happens when the user uninstalls one half of a paired
  Bridge? The `groupId` is now dangling on the surviving tunnel.
- **The `relayPolicy: Ask` value mentioned in §8.** The §2.1 rule only
  enumerates `Always | Never`; §8 row 3 says "per-tunnel `relayPolicy` (Always /
  Never / Ask)". What does Ask render as in the row? A pending banner forever?
- **§3.2's two-vs-one row presentation.** Open question §9.3 admits this; no
  proposal for which side wins. The bug-magnet is the transition between the
  two presentations: user creates a Bridge via Tile #3 (one row), uninstalls
  one half, the remaining tunnel becomes "two-row eligible" but is alone.
  What's the row count? One? Zero?
- **Permission-revocation deep-link on Android 13+.** §4.1's `ConsentDenied`
  remediation is "re-launch `VpnService.prepare()`". On Android 14, if the
  user has explicitly toggled the permission off in Settings, `prepare()` will
  return the consent intent again — but the system can also have flagged this
  app as "permission denied by user" and the intent silently fails on launch.
  No path forward in the design.
- **The `dropped same-uid` counter (§4 below-the-fold).** Today this counter
  exists in gvisor stats but isn't surfaced; §4 lists it as a feature. What's
  the unit? Bytes, packets, flows? The doc punts.
- **What happens when CASCADE-2 itself is buggy?** The current OFF-by-default
  posture is intentional ("until validation lands", `SettingsStore.kt:57-61`).
  The design removes the toggle and replaces it with per-tunnel policy — but
  per-tunnel policy doesn't help if the *implementation* has a regression.
  The escape hatch is gone.
- **No design for the multi-host case** (use case "multiple hosts" from the
  brief). The doc covers multiple joiners (via Joiner-N, already shipped) but
  is silent on N concurrent host tunnels' UX. Same Settings? Per-host listen
  port collisions?
- **The state machine doesn't model the wormhole-pairing flow's transient
  states.** A tunnel in mid-pairing isn't `Disabled` (we're actively doing
  something), isn't `Arming` (no transport yet), isn't `Connecting` (no
  handshake yet). The eight-state alphabet has no slot.
