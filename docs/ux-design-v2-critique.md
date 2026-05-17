# Critique of ux-design-v2.md — Round 2 (verification pass)

## 1. Verdict

**ship-with-amendments.** Three small must-fixes listed at the end. The
load-bearing pieces (state machine, transition log, three-signal phantom-active
detection, cascade default flip, dropped active probe) are sound. Round 3 is
not required.

## 2. Round-1 follow-up

| # | Item | Status | Why |
|---|------|--------|-----|
| M1 | `onRevoke` is the wrong callback | **Resolved.** v2 §1.2 + §6.1 enumerate three signals: `establish()` null (verified at `JoinerVpnService.kt:108-110`), `onRevoke` (cheap, narrow scope), and `MainActivity.onResume()` re-`prepare()` (verified at `MainActivity.kt:485-491`). LOC honestly rebudgeted to ~120-180. |
| M2 | Idle has no exit transition | **Resolved.** v2 §1.2 adds three Idle→Connecting triggers (tx packet via gvisor write, endpoint reconfigure, detail-screen foregrounding). |
| M3 | Cascade rule reversed | **Resolved with explicit pushback.** v2 §2.1 rewrites rule (2) against `HasCascadePrefix`; admits asymmetry is at *admit-direction*, not at the route-install level. Verified independently (see §4). |
| M4 | §2.3 Block-only-for-`0.0.0.0/0` misses RFC1918 | **Resolved.** v2 §2.3 cuts the heuristic; default is `Ask`, and the banner's leftmost (default) option is Block-always. Scenario B no longer leaks. |
| M5 | §6.2 active probe needs missing JNI + inbound reachability | **Resolved.** v2 §6.2 abandons the probe; replaced with sticky one-shot dialog + `Settings.ACTION_VPN_SETTINGS` deep-link on ARC. |
| S6 | Cut §7 drag-to-bridge | **Resolved.** v2 §7 deleted; long-press "Bridge with…" menu replaces it. |
| S7 | Reconcile switch vs. Paused-user | **Resolved.** v2 §3.1: switch is the sole pause-with-intent control; tap-row never changes state. |
| S8 | Freshly-imported start state | **Resolved.** v2 §1.1: `Disabled`. |
| S9 | `FailureCause.BrokerMissing` + broker URL surface | **Resolved.** v2 §4 / §4.1 add both. Uses existing `Tunnel.brokerWss` field. |
| S10 | Wrong WG constant attribution | **Resolved.** v2 §1.2 correctly attributes 180s = `RejectAfterTime`. |
| S11 | Cadence claim wrong (1s, not 5s) | **Resolved.** v2 §1.2 + §1.3 cite `WgrtcViewModel.kt:1868` at 1s. |
| N12 | Bonjour bullet | **Resolved.** Dropped from §5.1. |
| N13 | `humanMessage` i18n | **Resolved.** v2 §4.1 calls out `@StringRes`. |

All 5 must-fixes and all 8 should/nice-fixes resolved. No round-1 finding is
"made worse".

## 3. New attacks (capped at 5)

### A1 — `MainActivity.onResume()` re-prepare runs on a dead-activity timeline

**Claim**: v2 §1.2 row 3 + §6.1 step 3 lean on `MainActivity.onResume()` to
catch Settings-revoke at next foreground.

**Failure mode**: the dominant phantom-active scenario is the user *never*
foregrounding the app — they see only the FGS notification claiming Connected.
`onResume()` doesn't fire; the 1s `lastHandshakeTime` poll lives in the
ViewModel (Activity-scoped, not running); no Connect attempt means `establish()`
isn't called either. The registry stays stale for hours.

**Severity**: 3. Foregrounding fixes it; the symptom window can be days.

**Fix-shape**: also re-`prepare()` from OfferListenerService on a low-cadence
WorkManager job (e.g. every 30 min while any joiner-intent is on).

### A2 — `TunnelIntent` enum values undefined

**Claim**: v2 §12 adds `intent: TunnelIntent = TunnelIntent.NoIntentYet`; §3.1
says the switch writes `intent=off` on user-flip-off-while-Paused-system.

**Failure mode**: enum values aren't enumerated. With only `NoIntentYet | On |
Off`, freshly-imported and user-paused both serialise to `Off` — the
Disabled vs. Paused(user) distinction collapses across reboot.

**Severity**: 3.

**Fix-shape**: enumerate `NoIntentYet | WantsOn | ExplicitlyOff`; map
`ExplicitlyOff`→Paused(user), `NoIntentYet`→Disabled.

### A3 — `Pairing` failure isn't binary

**Claim**: v2 §1.1: `Pairing → Disabled` (success) or `Pairing →
Failed(permanent)` (user-abort / SAS-mismatch).

**Failure mode**: SAS-mismatch and broker-timeout are *retryable*. Lumping
them with user-cancel into permanent denies the natural "retype the code"
recovery.

**Severity**: 2.

**Fix-shape**: route SAS-mismatch / network-fail to `Failed(recoverable)` (or
re-enter `Pairing`); keep permanent for user-cancel / code-expired.

### A4 — §2.4 contradicts §9.7 on policy granularity

**Claim**: §9.7 says relay policy is per-tunnel; §2.4 says the banner "re-prompts"
when the next joiner comes up.

**Failure mode**: two policy models stapled together. An Allow-always answer
that listed *Work VPN* and *Lab Cluster* now silently extends to a third joiner
that just appears — but only if the banner is still on screen. Race-sensitive.

**Severity**: 3.

**Fix-shape**: pick one. Per-host (preferred — matches the §2 prose): drop the
re-prompt clause from §2.4. Per-pair: accept the N×M settings surface.

### A5 — §13 layer 3 doesn't reach release users

**Claim**: §13 layer 3: `K_CASCADE_FORCED_OFF` is settable "only via adb
broadcast on `.debug` / `.agent` builds".

**Failure mode**: regression victims are on `.release`. The only real recourse
is layer 2 (hotfix-via-Play). "Three layers of defence" is two for shipped
users.

**Severity**: 2.

**Fix-shape**: either drop the third bullet, or expose the flag via hidden
Settings long-press in release too.

## 4. Pushback evaluation

**Cascade direction (§2.1 pushback).** **Designer correct, round-1 critic was
wrong.** Verified at `cascade_ferry_registry.go:266-294`:
`createFerryLocked` installs **both** host-side routes (lines 278-288: joiner
AllowedIPs → ferry's host NIC) **and** joiner-side routes (lines 291-293:
host's peerSubnets → ferry's joiner NIC). The round-1 critique conflated
"user-visible admit-direction is asymmetric" with "the route install is
one-directional". Concession granted.

**§13 kill-switch.** Framing correct ("escape hatch shouldn't be primary
UX"). Implementation half-right — see A5. Layers 1 & 2 fine; layer 3 doesn't
help release users.

## 5. Implementation readiness

| Section | Rating |
|---|---|
| §1.1 nine-state alphabet (incl. `Pairing`) | Ready |
| §1.2 transition table | Ready |
| §1.3 invariants | Ready |
| §1.4 FGS suspend-when-all-paused | Ready |
| §2.1 cascade rule (rewritten) | Ready |
| §2.3 `Ask`-at-first-eligibility banner | Designed but unsized — three-button copy needs i18n + UX writing pass |
| §2.4 banner with multi-joiner enumeration | Still hand-wavy — see A4 |
| §3.1 row + switch | Ready |
| §3.2 groupId orphan handling | Ready |
| §4 + §4.1 detail screen + FailureCause enum | Ready |
| §5.1 three-tile first run + Tile #3 wizard | Designed but unsized — Tile #3 wizard flow itself isn't drawn |
| §6.1 three-signal phantom-active | Ready (but see A1 for the hours-long blind window) |
| §6.2 passive ChromeOS dialog | Ready |
| §7 long-press "Bridge with…" | Ready |
| §11 step 9 N-host UX | Still hand-wavy — port-collision UI, naming defaults are mentioned but not drawn |
| §12 schema migration | Ready (modulo A2 — `TunnelIntent` enum values undefined) |
| §13 rollback | Ready for layers 1 & 2; layer 3 mis-scoped (A5) |

## 6. The hardest scenario v2 still doesn't gracefully handle

**Scenario: phantom-active on a phone that's never re-foregrounded.**

User on Android 14 grants VPN consent at first connect. Joiner runs a week in
the background. User toggles wgrtc's VPN permission off in Settings → Apps (or
an OTA flips it). User never opens the app — only sees the FGS notification.

Walk-through under v2:

1. Permission revocation: kernel kills the VpnService. `onRevoke()` does
   **not** fire on Settings-revoke (≠ another-VPN-takeover).
2. FGS restarts sticky. `builder.establish()` isn't called — no Connect is in
   flight, the service doesn't proactively retry.
3. `MainActivity.onResume()` doesn't fire — user hasn't opened the app.
4. The 1s `lastHandshakeTime` poll lives in the ViewModel, which is
   Activity-scoped; with the activity dead it isn't polling.
5. Net: FGS notification keeps saying Connected. The registry has no signal.

**Gap**: all three of v2's signals require either a Connect attempt or a
foreground event. The phantom-active window is narrower than v1 but real.
Fix is A1 (low-cadence WorkManager re-`prepare()` driven by the FGS).

## 7. Two questions for the maintainer

1. **Is the OfferListenerService allowed to call `VpnService.prepare()`?** It's
   a Service, not an Activity; `prepare()` returning the consent Intent only
   matters if we have a UI to launch it from. If yes, A1's WorkManager re-check
   is trivial. If no, the phantom-active blind window in §6 has no clean fix
   from the service side.

2. **For `relayPolicy: Ask`, do you want one banner-answer per host (§9.7
   answer "per-tunnel") or per (host, joiner) pair (what §2.4's enumeration
   implies)?** The design currently does both. Pick one before implementation.

## Must-fix amendments (before ship)

1. **A2 — enumerate `TunnelIntent` explicitly** in §12 so `Disabled` vs.
   `Paused (user)` survives serialisation. Three values, half a paragraph.
2. **A4 — resolve §2.4 vs. §9.7** policy granularity. One sentence: choose
   per-host (preferred — matches §2 prose) and delete the
   re-prompt-per-new-joiner clause from §2.4.
3. **A1 — add a low-cadence re-`prepare()` from OfferListenerService** to §6.1
   step list (conditional on Q1's answer). Without it, FGS-only users can
   stay phantom-active for arbitrarily long.

Everything else from §3 is a follow-up issue, not a blocker. Ship.
