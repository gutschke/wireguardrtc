# UX v2 — Follow-up tasks after the v0.3.0 cut

Status: living document, updated as items land.
Audience: maintainers.
Scope: items the v0.3.0 release deliberately deferred.  None are
blockers; most are polish or low-frequency edge cases.

## Triage

| Item | Driver | Effort | Risk if shipped late |
|---|---|---|---|
| F1. Wormhole-aware Bridge variant | Tile #3 currently refuses wormhole/enroll URIs | small | low — explicit refusal text already shipped |
| F2. Direction-badge arrow glyphs | §11.4 follow-up polish | small | low — current icon-only renders correctly |
| F3. Bonjour / mDNS discovery (Tile #1 bullet 4) | Designer dropped as separate spec | medium | low — Tile #1 paths cover paste/QR/wormhole |
| F4. `reapplyCascadeForActiveSlots` dedicated test | Critic flagged as non-blocking follow-up | small | low — gate-at-consumer covers the load-bearing invariant |
| F5. `humanMessage` @StringRes migration | i18n preparation per §4.1 | small-medium | low — English-only ships fine |
| F6. Onboarding-tour pruning | Three-tile launcher (§11.6) supersedes the 3-page tour, but the tour still runs on first launch | small | low — duplicate-but-not-conflicting UI |
| F7. Settings hidden-toggle accessibility | TalkBack discovery of the §13 long-press | tiny | low — disabled flow renders red text |
| F8. Joiner-side test for the §13 gate | Critic noted gate-at-consumer doesn't directly pin joiner reapply | small | low — CascadeForcedOffGateTest covers the wiring layer |

## F1 — Wormhole-aware Bridge variant

**Symptom**: Tile #3 wizard's joiner step refuses wormhole / `wgrtc-enroll://`
URIs with the message "Bridge setup doesn't support wormhole / enroll
URIs yet — paste a raw [Interface] config, or cancel and use Tile #1 for
this tunnel."  The user has to bail out of the wizard.

**Why deferred**: `enrollAndAdd` is a long-running coroutine that may
emit OFFER round-trips, broker reconnects, and persisted-config writes
across multiple lifecycle events.  Tile #3's joiner-then-host
sequencing needs the joiner save's completion to be a single observable
event.  The existing `addLegacyTunnelInBridgeFlow` path is single-step;
wormhole is multi-step.

**Plan**:

1. Add `enrollAndAddInBridgeFlow(uri, deviceLabel, name)` to
   `WgrtcViewModel`: same shape as `addLegacyTunnelInBridgeFlow`,
   throws if no Bridge flow is in progress, stamps the pending
   groupId once the wormhole completes (NOT on entry — failure
   modes must leave the flow intact for retry).
2. Update `PasteTunnelScreen`'s `bridgeActive` branch to route the
   `wgrtc-enroll://` path through it.
3. Source-lint test: `enrollAndAdd` must not silently consume the
   Bridge flow; only `enrollAndAddInBridgeFlow` reads it.  Symmetric
   to the addLegacyTunnel / addHostModeTunnel lint pair.
4. Manual test on the emulator + 10.10.0.122: import a host-mode
   wgrtc-enroll URI as the joiner half of a Bridge, then configure
   the host.  Verify both halves get the same groupId; the
   TunnelList row collapses.

**Estimate**: 60-90 lines + 1 lint test.

## F2 — Direction-badge arrow glyphs

**Symptom**: per §3.1 the row should show a direction badge — "arrow
into a phone glyph" for host, "arrow out of a phone glyph" for joiner,
"two arrows" for a Bridge.  Today we render `Icons.Outlined.WifiTethering`
(host) / `Icons.Outlined.Login` (joiner) / `Icons.Outlined.SwapHoriz`
(Bridge) — close but not the literal directional glyphs the design
called for.

**Why deferred**: the existing icons communicate the same information.
The design's literal "arrow + phone" compound glyph would need either a
custom drawable or a stacked-icon Compose composable.

**Plan**:

1. Decide whether to ship custom drawables (smaller bundle, exact match)
   or compose two `Icons.Outlined.*` icons in a stack.
2. Update `TunnelCard` and `BridgeCard`'s badge boxes.
3. UX writing pass: do the new glyphs read as direction at thumbnail
   size?  A11y `contentDescription` must spell out "Inbound" /
   "Outbound" / "Bridge" regardless of glyph choice.

**Estimate**: 40-80 lines + 1 visual-regression manual check.

## F3 — Bonjour / mDNS discovery

**Symptom**: Tile #1 ("Join a network") currently offers paste, QR, and
wormhole only.  The design's earlier draft mentioned "discover via
Bonjour" but the round-1 critic dropped it as out-of-scope.

**Why deferred**: NSD/mDNS is a separate spec.  Implementation needs
service-type registration, multicast-permission consent, ARP-spoof
defence, and a UX for picking among multiple announced services.

**Plan**: write a separate design doc.  Out of scope until then.

## F4 — `reapplyCascadeForActiveSlots` dedicated test

**Symptom**: round-2 critic of §13 layer-3 flagged that the new
`HostModeBackend.reapplyCascadeForActiveSlots` method isn't directly
exercised by a test — it's only reached via WgrtcApp's flow collector.

**Plan**: in `HostModeBackendTest` (or a new `HostModeBackendCascadeTest`),
set up two slots — one paused, one active, one with
`relayPolicy=Always`, one with `Never` — and assert
`reapplyCascadeForActiveSlots` registers exactly the active+Always
slot.  Needs a recording `CascadeWiring.Bridge` to capture
`onHostBridgeUp` invocations.

**Estimate**: 80-120 lines.

## F5 — `humanMessage` @StringRes migration

**Symptom**: every `FailureCause` body string is currently an inline
literal in `TunnelListScreen.failureCopy`.  For non-English locales we'd
want them in `strings.xml` so `Context.getString(R.string.…)` reads
the localised version.

**Why deferred**: wgrtc ships English-only today; no locale infra in the
codebase.

**Plan**:

1. Move all failure copy + banner copy to `strings.xml`.
2. `failureCopy` returns `Triple<Int, Int, FailureRemediation?>` (ID
   pairs).  Callers resolve via `LocalContext.current.getString(...)`.
3. Tests assert IDs match — copy-content tests move to instrumented
   tests since `Context` is needed for `getString`.

**Estimate**: 200-300 lines, mostly mechanical.

## F6 — Onboarding-tour pruning

**Symptom**: the three-page first-launch tour
(`ui/OnboardingScreen.kt`) and the three-tile launcher (§11.6) both
ship.  A first-time user sees the tour, taps "Get started", lands on
the empty TunnelList → sees the tile launcher.  Not broken, just
redundant.

**Plan**: decide whether to drop the tour entirely or merge tour
page 1 + 2 + 3 into the tile launcher screen.  Design v2 §5.3
rejected "tour + carousel" combinations but this is a soft conflict.

**Estimate**: 50-150 lines depending on merge strategy.

## F7 — Settings hidden-toggle accessibility

**Symptom**: the §13 long-press affordance on the version label is
invisible to TalkBack — no `semantics { contentDescription }` or
custom action.

**Plan**: add `Modifier.semantics { customActions = listOf(...) }` so
TalkBack announces "Long press to access emergency cascade settings"
when focused on the version label.  Discoverable for screen-reader
users without changing the visual.

**Estimate**: ~20 lines.

## F8 — Joiner-side §13 gate test

**Symptom**: `CascadeForcedOffGateTest` pins
`CascadeWiring.setEnabled(false)` tearing down joiner state, but
doesn't pin the re-enable sweep on joiner-N (where it lives in
`JoinerNController`'s existing rebuild semantics).

**Plan**: extend `JoinerNControllerTest` with a case that exercises
`setEnabled(false) → … → setEnabled(true)` cycle and asserts the
joiner stack re-registers on next `addJoiner`.

**Estimate**: 40-80 lines.

---

## Risk register

Nothing in this list blocks ship.  The biggest user-visible gap is
**F1 (wormhole Bridge)** — a user who tries the §11.6 Tile #3 wizard
with a wormhole-source remote network hits the refusal message.
Estimated population: small (most wgrtc joiner imports today are
raw-config paste).  Mitigation: the refusal copy explicitly tells the
user what to do (cancel and use Tile #1).
