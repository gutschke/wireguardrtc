# Privacy Policy

**Effective date:** 2026-05-11

This privacy policy covers the **wgrtc Android application** (Google Play
package id `com.gutschke.wgrtc`) and the related `wireguardrtc` daemon hosted
in this repository. Both are open-source components of the same WireGuard
peer-discovery project; they share an end-to-end-encrypted signaling protocol
but are distributed and operated independently. Source for the Android client
will be merged into this repository before the first public release.

## Summary

- **No analytics, telemetry, or crash data is collected.** The application
  does not phone home.
- **WireGuard configuration, including private keys, is stored only on your
  device.**
- **The app's only outbound network connections are the WireGuard tunnel
  itself and the signaling broker you have configured.**
- **The signaling broker sees only routing identifiers derived from public
  keys, and end-to-end-encrypted payloads. It cannot read your tunnel
  configuration, traffic, or location.**
- **No data is shared with third parties** beyond the operator of whichever
  signaling broker you choose to use.

## Data we collect about you

**None.** The app does not include analytics SDKs, advertising SDKs, crash
reporters, or telemetry of any kind. We do not have a server that receives
data from you.

If you install the app from Google Play, Google Play itself collects standard
install and aggregate-usage metrics under
[Google's privacy policy](https://policies.google.com/privacy). These
statistics are visible to the developer in aggregate form only; they are not
linked to any individual user inside the app.

## Data stored on your device

The app stores the following locally, in its private app-storage area
(unreadable by other apps under Android's standard sandboxing):

- **Tunnel configurations**, including WireGuard private and public keys, peer
  public keys, allowed IP ranges, endpoint hints, and any per-peer
  enrolment metadata you've created.
- **Application preferences**, including the signaling broker URL you have
  selected and any feature flags toggled in the Settings screen.

This data never leaves your device unless you choose to back it up via
Android's standard backup mechanisms, or you explicitly copy a configuration
out (for example, by sharing an enrolment payload with another peer).

## Network connections the app makes

1. **WireGuard tunnel traffic.** Encrypted UDP between your device and the
   peers you have configured. The contents are inaccessible to anyone except
   the configured peers, by design of the WireGuard protocol.
2. **Signaling broker traffic.** A WebSocket connection (WSS, TLS-encrypted)
   to the broker URL you configure. The default is the public
   `0.peerjs.com` broker, which is fronted by Cloudflare; you can replace it
   in Settings with a self-hosted broker. The broker sees:
   - your IP address (necessarily, since you are connected to it),
   - **SHA-256 routing identifiers** derived from peer public keys (not the
     public keys themselves), and
   - **end-to-end-encrypted payloads** that the broker cannot decrypt. Keys
     are derived from a Diffie-Hellman exchange over your existing
     WireGuard key material, never from anything the broker provides.

   The broker cannot learn your tunnel configuration, your traffic, the
   identities of your peers, or your geographic location beyond the
   approximation given by your IP address.
3. **No other outbound connections.**

## Permissions the app requests, and why

- **`android.permission.INTERNET`** — required for the WireGuard tunnel and
  for signaling.
- **`android.permission.FOREGROUND_SERVICE`** and
  **`FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED`** — required to keep an
  active WireGuard tunnel running while the screen is off.
- **`android.permission.BIND_VPN_SERVICE`** (via Android's VpnService API) —
  required when you turn on a tunnel that you have configured the device to
  route traffic through. Android will display a system consent prompt the
  first time you do this. We use VpnService only to route traffic through
  tunnels you have explicitly configured; we do not redirect traffic to any
  wgrtc-controlled server.
- **`android.permission.CAMERA`** — optional, only requested when you tap the
  in-app "Scan QR code" affordance during peer enrolment. The camera is
  active only while that screen is open; no images are stored.
- **`android.permission.POST_NOTIFICATIONS`** — used solely for the
  foreground-service notification that Android requires while a tunnel is
  active.

## Children

The app is not directed to children under 13 and does not knowingly collect
information from anyone.

## Open-source code

The source code for both the Android application and the `wireguardrtc`
daemon is available in this repository under the licence stated in the
`LICENSE` file. You can verify the behaviours described in this policy by
auditing the source directly.

## Changes to this policy

If we change this policy in a way that affects how data is handled, we will
update the **Effective date** above and note the change in the repository
commit history. For users who have installed the app from Google Play,
significant changes will also be reflected in the Play Store listing.

## Contact

Questions or concerns about this policy may be sent to
**`gutschke@users.noreply.github.com`** or filed as an issue on this
repository.
