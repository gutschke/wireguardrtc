# Android Networking & VPN Apps — Investigation Findings

This document captures lessons learned from a multi-hour debugging session on
2026-05-08 where the wgrtc Android app's network access was completely blocked
for its uid in ways that *every* public Android API claimed wasn't happening.
Distinguishes between things we **verified directly** in logs/dumps,
things that are **likely true** (consistent with observations but not
proven), and **speculation** (theories we never confirmed). When you hit a
similar "uid is silently dropped" situation in the future, work the
diagnostic ladder in this document before reaching for `adb uninstall +
reboot`.

## TL;DR

When an Android app's outbound TCP times out from its own uid but works
from `adb shell` (uid 2000) — and `dumpsys netpolicy`, `NetworkCallback
.onBlockedStatusChanged`, `restrictBackgroundStatus`, and the
firewall-chain rules **all say "not blocked"** — the most likely cause is
an eBPF-layer per-uid filter installed by Adaptive Battery / App Standby,
which is invisible to the public diagnostic APIs. The reliable recovery
is `adb uninstall <pkg>` → reboot → reinstall. Repeated rapid
install/kill cycles (e.g., during heavy debug iteration) appear to
trigger the classification.

## What's confirmed vs. what's theory

| Statement | Confidence | Evidence |
|---|---|---|
| `nc` from `adb shell` (uid 2000) reaches LAN/internet hosts that the app's TCP can't | **Confirmed** | Direct test: `adb shell nc 198.51.100.107 443` returned HTTP within ms; `adb shell run-as <pkg> nc 1.1.1.1 443` hung 5s+ |
| `NetworkCallback.onBlockedStatusChanged` reported `blocked=false` while the uid was empirically blocked | **Confirmed** | logcat |
| `dumpsys netpolicy`'s firewall-chain entries (`-allow`, `-default`, `-deny`) for the uid did not have any chain in `-deny` for the uid in foreground/TOP | **Confirmed** | `dumpsys netpolicy` output verified by inspection |
| `effective=NONE` in the per-uid `blocked_state` while in TOP/foreground | **Confirmed** | Same dump |
| Binding the okhttp client's `socketFactory` to `Network.socketFactory` does NOT bypass the block | **Confirmed** | Both unbound and bound socket probes timed out |
| The block is **uid-bound**, not destination-bound | **Confirmed** | App couldn't reach `1.1.1.1`, `198.51.100.107`, or anything else; shell uid could reach all of them on the same network |
| `adb uninstall + reboot + reinstall` clears the block | **Confirmed** | Done; subsequent enrollment + connect worked end-to-end |
| The block was caused by repeated install/kill cycles during debugging | **Likely** | Cycling correlation; we did dozens of reinstalls in <1 hour, exactly the kind of churn that triggers Adaptive Battery's "restrict this app" classification on Pixel |
| The mechanism is an eBPF per-uid drop rule installed in a cgroup | **Likely (not confirmed)** | Process of elimination — every documented Android mechanism (NetworkPolicy, iptables firewall chains, VpnService routing, per-network policy) reported "not blocking" while behavior was consistent with a kernel-level drop. Modern Android (14+) moved per-uid filtering largely to BPF, and BPF state isn't enumerated in `dumpsys netpolicy`. **We did not run `bpftool prog dump` to verify** (would need root) |
| The "Background data" toggle in user-visible Settings was reportedly ON, but `dumpsys netpolicy` showed `policy=1 (REJECT_METERED_BACKGROUND)` | **Confirmed observation; mechanism unclear** | The discrepancy may be: (a) Pixel firmware UI lag, (b) the policy bit is set but doesn't itself drive the foreground block, (c) something else writes the bit independently of the toggle |
| `policy=1 (REJECT_METERED_BACKGROUND)` alone restricts only metered+background, not unmetered+foreground | **Documented but contradicted by observation** | Per Android docs the policy should be a no-op when the active network is unmetered (WiFi) and procState is TOP. We observed the block anyway. The `policy=1` setting may be a *correlate* of the actual blocking mechanism (both set by the same triggering event), not the cause |
| The VpnService per-uid routing trap (where untagged sockets from a VPN-provider uid go into a non-existent `tun0`) is real, but **wasn't the cause here** | **Disproved for this case** | Bound-to-Network probe also failed; that probe explicitly bypasses the trap |

## Architecture: layers Android applies to outbound traffic from app uids

When an app calls `socket.connect(...)`, the packet traverses several
filtering layers before reaching the wire. Each layer can drop the
packet, and each surfaces (or doesn't) in a different diagnostic.

```
                    ┌──────────────────────────────┐
                    │ App: socket.connect(host:port)│
                    └──────────────┬───────────────┘
                                   ▼
       (1) Per-process binding: ConnectivityManager.bindProcessToNetwork()
           — affects ALL sockets in this process. Rare; typically null.
                                   │
                                   ▼
       (2) Per-socket Network binding: Network.socketFactory / bindSocket()
           — affects this specific socket. Sets fwmark on the socket so
             the routing rules pick a specific table.
                                   │
                                   ▼
       (3) Routing rules (`ip rule show`) → routing table (`ip route show table N`)
           — Android has dozens of `ip rule` entries with priority + uidrange
             + fwmark + iif/oif filters. They route based on socket fwmark.
             Per-uid-pinned apps (Google Photos, gms, certain system apps)
             get their own table (e.g., 1000000047) with NO default route,
             which is how Android implements per-uid restrictions.
                                   │
                                   ▼
       (4) iptables firewall (legacy, partial) + eBPF cgroup filters (modern)
           — These can drop packets by uid, regardless of routing.
             `dumpsys netpolicy` enumerates **only the iptables view**.
             eBPF rules are NOT enumerated there — `bpftool prog dump`
             is needed (root only).
                                   │
                                   ▼
       (5) VpnService per-uid trap (only for VPN-provider apps)
           — When an app declares a VpnService with active routes, Android
             routes ALL packets from that app's uid into `tun0`, EXCEPT
             those bound to a specific Network or `VpnService.protect()`'d.
                                   │
                                   ▼
       (6) Kernel network stack → wire
```

The diagnostic challenge is that **layers 4 and 5 silently drop packets**
(no ICMP, no socket error, just a `SocketTimeoutException` after the
read/connect timeout), and modern Android uses layer-4 BPF rules that
are not enumerated by any public API.

## Observable diagnostic surfaces

What you can ask, what each tells you, and what each *doesn't* tell you.

### `ConnectivityManager.getRestrictBackgroundStatus()`
Returns one of `DISABLED (1)`, `WHITELISTED (2)`, `ENABLED (3)`.

- **What it actually means**: app's status with respect to **Data Saver**
  on metered networks. `ENABLED` means "if the active network were
  metered AND we were in background, traffic would be restricted."
- **What it doesn't mean**: it does NOT necessarily mean traffic is
  being blocked right now. Confusingly, it can return `ENABLED` even
  when the device's `Restrict background: false` global flag is off,
  because `ENABLED` reflects the per-app `policy=REJECT_METERED_BACKGROUND`
  bit (`netpolicy`), not the global Data Saver state.
- **What we observed**: returned `ENABLED (3)` for our uid even when
  the global Data Saver was off, the network was unmetered WiFi, and
  the app was foreground. The status was a correlate of "something is
  set" but not directly the blocker.

### `NetworkCallback.onBlockedStatusChanged(network, blocked: Boolean)`
The public API surface for "is this uid blocked on this network?"

- **What it tells you**: Android's *NetworkPolicyManager*'s opinion of
  whether the uid is blocked on the given network. Authoritative for
  policy-layer blocks (Doze, Battery Saver, App Standby, Restricted
  Mode, Lockdown VPN, Low Power Standby).
- **What it doesn't tell you**: anything about layer-4 BPF filters or
  layer-5 VpnService trap. We observed `blocked=false` while
  empirically the uid couldn't reach anywhere.
- **The hidden-API `Int` overload** (`onBlockedStatusChanged(Network, blocked: Int)`)
  carries a bitmask of specific reasons (BATTERY_SAVER, DOZE,
  APP_STANDBY, RESTRICTED_MODE, LOCKDOWN_VPN, LOW_POWER_STANDBY,
  METERED_DATA_SAVER, METERED_USER_RESTRICTED, METERED_ADMIN_DISABLED).
  **Hidden API**, only callable via reflection or
  `@RequiresApi(...)` paths in apps with `@SuppressLint("RestrictedApi")`.
  We didn't use this in production code; the Boolean variant gave us
  enough.

### `dumpsys netpolicy`
The most useful single dump.

- **Authoritative for**: per-uid `policy=` bits, the firewall-chain
  rules (background, standby, metered_allow, metered_deny_user,
  metered_deny_admin), the recent firewall-rule-change history with
  timestamps, the global `Restrict background` / `Restrict power` /
  `Device idle` / `Restricted networking mode` / `Low Power Standby
  mode` flags, and the `blocked_state` for each uid (which combines
  procState with the policy to produce the policy-layer's effective
  decision).
- **Doesn't include**: BPF rules, VpnService routing rules, MDM-imposed
  rules, OEM-specific extensions (e.g., Pixel's Adaptive Battery
  internals).
- **Key fields**:
  - `policy=N (NAME)` — persistent per-app policy bit (e.g., `1
    REJECT_METERED_BACKGROUND` corresponds to "Background data: OFF"
    in user UI)
  - `state={procState=TOP, ...}` — current process state
  - `blocked_state={blocked=A|B, allowed=X|Y, effective=NONE/Z}` — the
    policy engine's view: `blocked` is what *would* block in the
    abstract, `allowed` is the foreground-style overrides currently in
    effect, `effective` is the net result. **`effective=NONE` means
    the policy engine isn't blocking — but doesn't mean nothing else
    is.**
  - `Firewall rule changed: <uid>-<chain>-<rule>` history — useful for
    seeing whether a chain's rule for the uid recently changed (e.g.,
    `metered_deny_user-deny` → `metered_deny_user-default` when an app
    goes to foreground)

### `dumpsys connectivity`
- Authoritative for: active networks, their capabilities, link
  properties (interface name, IPs, DNS, routes), per-network
  NetworkRequest registrations, default routes for the system and per
  user.
- Doesn't show: per-uid blocking decisions.

### `adb shell ip rule` / `ip route show table all`
- Authoritative for: kernel-level routing rule chain. Shows uid-pinned
  rules (`uidrange XXX-XXX lookup TABLE_N`) and fwmark-based rules
  (`fwmark 0xMASK/0xVALUE lookup TABLE_N`).
- Limitation: shows what tables exist for which fwmarks/uids; doesn't
  show what fwmark a particular socket gets. Sockets get a fwmark
  based on the Network they're bound to (or no fwmark if unbound).

### `adb shell run-as <pkg> <command>`
- **The most useful single test** for "is this a uid issue?"
- Runs `<command>` (e.g., `nc`, `curl`) as the app's uid in a fresh
  shell process. Filesystem and network policy match the app's uid.
- If the command works as `adb shell nc ...` but hangs as `adb shell
  run-as <pkg> nc ...`, the issue is uid-specific. Cuts the search
  space immediately.
- Requires the app to be `android:debuggable="true"` in the manifest.

### `adb shell dumpsys netd`
- **Doesn't exist** on Pixel (per the user's test on 2026-05-08).
  `dumpsys netd` is not a known service. Possibly was deprecated or
  renamed. Don't rely on this.

### What would be useful but requires root
- `bpftool prog dump` — list BPF programs attached to network paths.
- `bpftool map dump` — list BPF maps containing per-uid drop lists.
- `iptables-save` — full iptables ruleset.
- `cat /proc/net/xt_qtaguid/iptables_counters` — per-uid traffic
  counters (deprecated on modern Android but sometimes still works).

## What we tried that didn't help

| Thing | Why we tried | Why it didn't help |
|---|---|---|
| `OkHttpClient.Builder.connectTimeout(30, SECONDS)` | Cold-WiFi wake delay theory | Block was uid-level, no time would have helped |
| `OkHttpClient.Builder.eventListener(...)` for phase-by-phase logging | Distinguish DNS/TCP/TLS/HTTP failures | Useful logging in general but EventListener didn't fire on WebSocket connections in okhttp 4.12 — bytecode contains the strings, but callbacks weren't invoked at runtime. Reason still unclear. **Worked around by adding a custom `Dns` wrapper, which DID fire and gave us the DNS resolution timing.** |
| `BrokerNetworkPin` (Network.socketFactory binding for okhttp clients) | VpnService per-uid trap theory | Bound-to-Network probe also timed out. Confirms the block is below the routing layer — it can't be bypassed by selecting a different network |
| Increasing `ConnectionRunner.perCandidateTimeoutMs` from 5s → 12s | Race-vs-WG-retry boundary theory | Real bug at one point (5s timeout fired exactly when WG would retry handshake), but irrelevant when uid is blocked entirely |
| `VpnService.protect(socket)` (would have, didn't actually try) | The documented bypass for VPN-provider apps | Couldn't easily get a service instance and the bound-Network probe already proved the trap wasn't the cause |
| Toggling Background data off/on in user-visible Settings | Clear the per-app policy bit | User reported toggle was already ON, yet policy bit was set. Toggling didn't change behavior |

## What did work

`adb uninstall com.gutschke.wgrtc.debug` → reboot the phone →
`adb install -r app-debug.apk`. End-to-end functionality restored
immediately after.

This strongly suggests:
- The blocking state is keyed on the (uid, package-install-instance)
  pair, not on the package name alone. Reinstalling under a fresh
  install record clears the association.
- The reboot is **probably necessary** because some BPF state lives in
  netd's memory and only resets when netd restarts. We didn't try
  uninstall-without-reboot to verify whether reboot was strictly
  required.

## How to debug a blocked-uid mystery

Order from cheapest to most invasive:

1. **`run-as` test.** `adb shell run-as <pkg> nc <host> <port>`. If it
   hangs while `adb shell nc <host> <port>` works, the issue is
   uid-specific and you can stop guessing about destinations or
   protocols.

2. **Probe a known-good public IP from the app.** `1.1.1.1:443` is
   universal and unmetered everywhere. If even *this* fails, the block
   isn't destination-specific.

3. **Capture `dumpsys netpolicy` and grep for the uid.**
   - If you see `policy=N (REJECT_METERED_BACKGROUND)` etc. — note it
     but understand it doesn't necessarily mean foreground is blocked.
   - Look at `state={procState=TOP, ...} blocked_state={effective=...}`
     for the uid. If `effective=NONE`, the policy layer isn't blocking
     and you should suspect BPF.

4. **`NetworkCallback.onBlockedStatusChanged`.** Confirm `blocked` for
   each network (cheap to add as an `Application.onCreate` listener;
   we have this in `WgrtcApp.registerBlockedStatusListener`).

5. **Bound vs. unbound probe.** Try a `Socket()` connect with
   `Network.socketFactory.createSocket()` and a vanilla `Socket()`. If
   bound succeeds and unbound fails: VpnService trap. If both fail:
   layer-4 (BPF/iptables) block.

6. **Check VPN registrations and "Always-on VPN" status.** Settings →
   Network & internet → VPN → tap each entry. "Always-on VPN" + "Block
   connections without VPN" turns the VpnService trap into a hard
   block (no escape via `protect()`). Forget any stale entries.

7. **Last resort: uninstall + reboot + reinstall.** Clears all
   accumulated per-app state. Use `adb install --user 0` to keep the
   install scoped to the primary user (avoids the cross-profile
   "briefcase" copy).

## How we (probably) got into this state

- During debugging we cycled `adb install -r ./app-debug.apk` 30+ times
  in under an hour. Every install kills the running process.
- Pixel's Adaptive Battery classifier runs in the background and
  monitors app behavior. Apps that are repeatedly killed and restarted
  abnormally can be classified as "misbehaving" and placed in a
  restricted standby bucket.
- Once placed there, **the BPF rules and `policy=1` bit are set**.
  These persist across:
  - App restarts ✗ (state still applies)
  - Toggling the user-visible "Background data" switch ✗ (we tried;
    didn't help)
  - VpnService `Forget VPN` ✗ (didn't help)
  - **Uninstall + reinstall** ✗ on its own (the user re-installed
    several times during the debug session — this didn't help, though
    we never tried just uninstalling and waiting before reinstalling)
  - **Uninstall + reboot + reinstall** ✓ (reset)

**Mitigating practices going forward:**

- Don't install over the running app dozens of times in rapid
  succession. Use `adb install -r --no-streaming` only when needed; for
  iterative development, `adb shell am force-stop <pkg>` then `adb
  install` is gentler than killing-via-install.
- For UI-only iteration, `adb shell am start` to relaunch is even less
  abusive.
- If the app **must** be reinstalled often (debugging the install path
  itself), space out the cycles or accept that the device may
  occasionally need a reset.

## Pixel-specific behaviors we observed

- The phone has multiple users (0, 10, 11) — primary, work profile,
  and possibly a guest. This is invisible until you check `pm list
  users`. Triggers a "briefcase" icon in the launcher and status bar.
- `adb install` (without `--user`) installs the APK into all users.
  Each install creates a separately-uid'd copy (uid 10440 in user 0,
  1010440 in user 10, etc.) with independent network policy state.
- Adaptive Battery: blackbox classifier that may impose restrictions
  invisible to public APIs. Reset path is uninstall + reboot.
- Pixel-Specific note: `dumpsys netd` is NOT a recognized service on
  Android phone / Android 15. Use `dumpsys netpolicy` and `dumpsys
  connectivity` instead.

## Things to verify if revisiting this

- **`bpftool prog dump`** with root would tell us authoritatively
  whether a per-uid BPF drop rule was actually present. We never ran
  this. Until someone does, "BPF rule" remains our best inference but
  not a verified fact.
- The exact threshold/heuristic Adaptive Battery uses to classify an
  app as "restricted." Google publishes vague guidance but not the
  specific signals.
- Whether `cmd netpolicy set restrict-background-uid <uid> false` from
  `adb shell` clears the policy bit (requires `MANAGE_NETWORK_POLICY`,
  may not work without root). We didn't try.
- Whether toggling the per-user-visible "Background data" while
  observing `dumpsys netpolicy` changes the `policy=` bit in real
  time, or whether the bit is detached from the toggle. We didn't
  isolate this experiment.
- Whether **just** reinstalling (without reboot) is enough — we
  reinstalled multiple times during debug without reset. Strong
  evidence that reinstall alone isn't enough, but not strictly
  controlled (each reinstall happened in the middle of other
  state changes).

## Code in the project that captures the diagnostic loop

- `app/src/main/kotlin/com/gutschke/wgrtc/WgrtcApp.kt` —
  `logNetworkPolicySnapshot()` runs at app startup, logs the active
  network, capabilities, blocked status, both bound and unbound TCP
  probes to `1.1.1.1:443`. Detects the "broad outbound block"
  scenario and sets `networkBlockDetected` for the UI to surface.
- `signalling/src/main/kotlin/com/gutschke/wgrtc/signalling/BrokerNetworkPin.kt` —
  Tracks a non-VPN `Network` and exposes its `socketFactory` for
  okhttp clients. Built for the VpnService-trap case, kept in code as
  defense-in-depth even though that wasn't the cause here.
- `EnrollClient.kt` — okhttp `EventListener` (added but observed not
  to fire on WebSocket flows; reason unknown, likely an okhttp 4.12
  quirk) and a `Dns` wrapper that DOES fire and is the more useful
  diagnostic.

## Hooks we should add if this happens again

- A unit/foreground "outbound canary" thread that runs an
  in-app probe to `1.1.1.1:443` every N minutes. If it transitions
  from "works" → "fails," log loudly and surface to the user before
  they hit the real broker failure.
- A startup-time `dumpsys netpolicy` capture (we'd need a runtime
  shell-out, not always allowed) so the diagnostic context is
  attached to the app's own log instead of requiring `adb` access.
- Memorialize the recovery procedure as a user-visible
  troubleshooting step in the network-blocked dialog: "If toggling
  Background data doesn't help: uninstall, reboot the phone, and
  reinstall."
