# Play Store listing copy

Paste-ready text for the Console's "Main store listing" form.

## App name (≤30 chars)

```
wgrtc
```
(5 / 30)

## Short description (≤80 chars)

```
Self-hosted, peer-to-peer WireGuard tunnels with NAT traversal.
```
(62 / 80)

Alternates if you want a different tone:

- `Peer-to-peer WireGuard tunnels. No relay, no central server.` (60)
- `WireGuard between two NATs — bring your own broker.` (51)
- `Self-hosted WireGuard with peer-to-peer NAT traversal.` (54)

## Full description (≤4000 chars)

```
wgrtc sets up direct WireGuard tunnels between peers that sit behind NAT —
without relay servers, static IPs, or kernel patches.

WireGuard is fast, modern, and stateless. That last property makes it
beautiful to operate but awkward to bootstrap when both endpoints are on
home or mobile networks: neither side knows the other's current public
address, and a kernel WireGuard handshake can't fire until both sides do.
wgrtc solves that by piping a brief, end-to-end-encrypted exchange of
endpoint hints through a signaling broker you control, performing
simultaneous UDP hole-punching on both NATs, then letting WireGuard itself
take over and run.

WHAT IT IS

— A WireGuard tunnel manager for Android (phone, tablet, ChromeOS).
— Built around the standard wireguard-go core; no patched kernel needed.
— Compatible with the same keys, config format, and protocols you already
  use on a Linux server, OpenWrt router, or any other WireGuard peer.

WHAT MAKES IT DIFFERENT

— Peer-to-peer by design. No relay server in the middle of your traffic.
— Self-hosted signaling. Point the app at your own signaling broker (or
  any compatible one); only short-lived metadata transits, encrypted.
— Two enrollment paths to your liking: scan a QR code, or read out a
  short SAS-protected wormhole phrase from one device to the other.
— No accounts, no cloud, no telemetry.

WHAT IT DOESN'T DO

— Marketing. There is no "premium tier", no subscription, no upsell.
— Phone home. No analytics, no crash reporting, no usage metrics.
— Promise the impossible. Symmetric-NAT-to-symmetric-NAT bypass is
  mathematically out of scope; cone-NAT setups (the vast majority of
  consumer ISPs and mobile networks) work as intended.

HOW IT WORKS, BRIEFLY

1. Two peers each connect to the signaling broker you've configured.
2. They exchange encrypted endpoint hints; the broker sees only routing
   IDs derived from public keys and ciphertext it cannot decrypt.
3. Both peers send a single raw UDP packet to the other's public address,
   simultaneously, opening their respective NATs.
4. The WireGuard handshake completes through the now-open path. The
   broker is no longer in the loop; the tunnel is direct.

PRIVACY

WireGuard configuration, including private keys, lives only on your
device. The app makes outbound connections only to (a) your WireGuard
peers and (b) whichever signaling broker you have configured. The
broker cannot read your tunnel traffic, your configuration, or the
identity of your peers.

Full policy: https://github.com/gutschke/wireguardrtc/blob/main/PRIVACY.md

OPEN SOURCE

The underlying `wireguardrtc` daemon and protocol design are open source
at github.com/gutschke/wireguardrtc; the Android client source will be
merged into the same repository before the first public release.

REQUIREMENTS

— Android 8.0 (API 26) or later, or a ChromeOS device with Android app
  support.
— A WireGuard endpoint to talk to. Either run the open-source
  `wireguardrtc` daemon on a Linux host you control, or use any
  WireGuard-compatible peer that can be reached through hole-punched
  UDP.
— A signaling broker you trust. The app ships with a default that you
  can — and probably should — replace with your own.

This is a tool for people who want to run their own VPN, not a consumer
VPN service. If you're looking for click-once anonymous internet, this
is not it.
```

Character count: ~3 200 / 4 000.

## Other listing fields

- **Application category**: Tools
- **Tags / search keywords**: WireGuard, VPN, networking, P2P, NAT
  traversal, self-hosted
- **Contact email**: `gutschke@users.noreply.github.com`
- **Website**: `https://github.com/gutschke/wireguardrtc`
- **Phone**: leave blank (Play allows this for individual accounts).
- **Privacy policy URL**:
  `https://github.com/gutschke/wireguardrtc/blob/main/PRIVACY.md`

## Graphic assets in this directory

| File | Dimensions | Where it goes in the Console |
|---|---|---|
| `feature-graphic.png` | 1024×500 | "Feature graphic" |
| `app-icon-512.png` | 512×512 | "App icon" (Play also extracts one from the AAB; uploading this gives crisper edges) |
| `feature-graphic.svg` | source | — (keep for future edits) |
| screenshots — see below | 320–3840 px short side; 16:9 or 9:16 | "Phone screenshots" (at least 2; 4–8 ideal) |

## Taking screenshots

Plug in the Pixel, install the new debug APK, set up the app the way a
real user would see it (at least one tunnel + an active host, ideally a
connected peer too), then capture each screen via adb. Use a state
that's representative of typical use — Play's reviewers reject obvious
mock data.

```bash
# From the android/ directory, with the phone connected via USB:

# 1. Install the freshly built debug APK
adb install -r app/build/outputs/apk/debug/app-debug.apk

# 2. Take screencaps and pull them
for shot in tunnel-list tunnel-detail host-invite settings; do
  adb shell screencap -p /sdcard/wgrtc-$shot.png
  adb pull /sdcard/wgrtc-$shot.png playstore-assets/
  adb shell rm /sdcard/wgrtc-$shot.png
done
```

Suggested set (4 screenshots covers Play's 2-min and gives a real feel
of the app):

1. **Tunnel list** with one or two tunnels configured. Default
   landing screen.
2. **Tunnel detail** for an active host tunnel — status hero showing
   "connected", the enrolled-peers section visible.
3. **Invite a peer** modal — three enrollment options (QR / wormhole
   code / manual config). Shows the differentiator.
4. **Settings** — broker URL field is the one to highlight.

For ChromeOS shots later, the equivalent path is
`vmc start termina` → ChromeOS's screenshot tool (Ctrl+) on the
Linux/Android window.

## Future graphic work, if you ever go beyond internal testing

- Localised store listings (Spanish, French, German, etc.) — Play lets
  you do this incrementally; English-only is fine for now.
- Tablet screenshots (7" + 10") — not required, but listings with them
  look complete.
- Short marketing video (≤2 min) hosted on YouTube — optional.
