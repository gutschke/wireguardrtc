# Play Console — FOREGROUND_SERVICE_SPECIAL_USE justification

Paste-ready text + video script for the Console's "Special use" form.

## Background

We declare a single foreground service of type `specialUse`:
`OfferListenerService`. It maintains one TLS WebSocket connection
(WSS, port 443) to a user-configured signaling broker. The
connection is signaling-only — no media, no telemetry — and exists
so that when a peer's WireGuard endpoint IP changes (the user
roams between WiFi and cellular, an ISP gives a new DHCP lease,
etc.), the app receives an encrypted endpoint hint and re-pins the
tunnel without user intervention.

None of the standard `foregroundServiceType` values fit:

- **`dataSync`** — Android 14+ caps each `dataSync` FGS at six
  cumulative hours per 24-hour window. Signaling needs to be
  always-on or the user's tunnels silently break the moment the
  peer's IP next rolls.
- **`connectedDevice`** — intended for foreground services that
  manage a hardware peripheral (Bluetooth, USB, sensor). Our
  service is purely network-side.
- **`mediaPlayback` / `microphone` / `camera` / `location` /
  `phoneCall`** — obviously unrelated.
- **`systemExempted`** — reserved for system-privileged categories
  (DPCs, accessibility, IMEs). We are none of these.

The `specialUse` type is the documented catch-all for foreground
services whose use case is not covered by the others. We provide
the required `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` `<property>` tag
inside the service declaration, with a plain-language description.

## Text justification (paste into the Console form)

```
wgrtc is a peer-to-peer WireGuard tunnel manager. The
foreground service OfferListenerService maintains a single
long-lived TLS WebSocket connection (WSS, port 443) to a
user-configured signaling broker. The connection is
signaling-only — no media, no telemetry. Its purpose is to
receive end-to-end-encrypted notifications when a remote
peer's WireGuard endpoint IP changes (cellular handoff, DHCP
lease renewal, network roaming), so the app can update the
tunnel endpoint and continue routing the user's traffic
through the WireGuard connection they have configured.

Why a foreground service: the listener must remain
connected for the entire lifetime of any active tunnel —
typically hours or days. Endpoint-change notifications
arrive unpredictably and the app must be able to respond
within seconds, otherwise the tunnel sits dead until the
user manually intervenes. Without a foreground service the
OS would kill the process minutes after the user switches
away from the app, breaking every tunnel they have set up.

Why specialUse: no standard foregroundServiceType fits.
dataSync is capped at 6 cumulative hours per day on Android
14+, which would silently break tunnels whenever the cap is
hit. connectedDevice covers hardware peripherals
(Bluetooth, USB, sensors), which we do not touch.
mediaPlayback, microphone, camera, location, phoneCall, and
systemExempted are obviously unrelated. The use case is
inherently long-lived background network signaling that
does not map to any of the standard buckets, which is
exactly the situation specialUse is documented to cover.

User-visible benefit: tunnels stay connected automatically
as peers roam between networks. The persistent notification
is dismissible from the user's in-app settings; the service
keeps signaling either way.
```

Character count: ~1 720. Console accepts up to 2 000.

## Video requirements (≤30 s, ≤100 MB, MP4)

Goal: show the reviewer (a) the FGS is actually running, and (b) the
user-visible benefit it produces. The video does NOT need to (and
realistically cannot) demonstrate the negative case "without FGS the
tunnel breaks" — that pathology only manifests after several minutes
of the process being backgrounded, which is not filmable in 30 s.
The negative argument lives in the text justification above.

Suggested sequence — each beat ~5–8 s:

1. **App in foreground**, tunnel detail screen, status "Connected"
   with a live endpoint (e.g. `198.51.100.103:22111`) and a recent
   handshake age. Linger long enough that the reviewer can read
   the status line.
2. **Swipe down the notification shade**: the OfferListenerService
   notification is visible. This is the visual proof that the FGS
   exists and is currently running. Hold the shade open for ~2 s
   so it's unambiguous.
3. **Toggle WiFi off** in Quick Settings. (The phone falls back
   to cellular.) Return to the app screen.
4. **The tunnel re-pins itself** to the public endpoint
   (`203.0.113.5:22111` in your setup) within roughly 20 s.
   The endpoint chip on the tunnel detail screen flips from the
   LAN address to the public address — no user action.

That is the entire demo. Steps 1–2 establish that the FGS is running;
steps 3–4 establish the benefit. The reviewer infers from the text
justification that maintaining this behaviour while the app is
backgrounded for hours requires the FGS.

### What NOT to film (would mislead the reviewer)

- **Don't** try to "disable the FGS" by toggling the in-app
  "Hide listener notification" setting or by disabling the
  notification channel in system Settings. Neither of those
  actions actually stops the FGS — they only hide the
  notification. The listener keeps running and roams continue to
  work. Filming this would suggest the FGS is decorative when in
  fact it is the thing keeping the process alive while
  backgrounded.
- **Don't** try to film a "no-FGS = broken" comparison. Inside a
  30 s window the OS has not yet had the idle time it needs to
  consider killing a backgrounded process, so the comparison
  wouldn't reproduce the failure mode the FGS prevents.

### Recording commands

```bash
# Pixel-side, with USB debugging on:
adb shell screenrecord --time-limit 30 --size 1080x2400 /sdcard/wgrtc-fgs.mp4
# Press Ctrl+C when done; the file is on the phone.
adb pull /sdcard/wgrtc-fgs.mp4 playstore-assets/
adb shell rm /sdcard/wgrtc-fgs.mp4
```

If the file is too large for the Console (default ~100 MB), shrink
with:

```bash
ffmpeg -i playstore-assets/wgrtc-fgs.mp4 \
  -vf "scale=720:-2" -c:v libx264 -crf 28 -preset slower \
  -movflags +faststart \
  playstore-assets/wgrtc-fgs-compressed.mp4
```

## Common rejection reasons (avoid them)

- "Video does not demonstrate the special use." — make sure the
  foreground-service notification is visible in the recording.
- "The use case appears to fit a standard FGS type." — the text
  above pre-empts this by walking through why each standard type
  fails. Don't trim it.
- "No persistent user benefit." — beat 3 of the video script
  (auto-roam) makes the benefit concrete.

## What goes where in the Console

| Field | Value |
|---|---|
| **Foreground service type** | Other (Special use) |
| **Subtype text** | (already in the manifest's `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` — Console should pre-fill from the AAB) |
| **Justification** | the paste-ready text above |
| **Video URL / upload** | record per the script, upload the `.mp4` |
