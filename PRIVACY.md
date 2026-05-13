# Privacy Policy

**Effective date:** 2026-05-11

This privacy policy covers the **wgrtc Android application** (Google Play
package id `com.gutschke.wgrtc`) and the **`wireguardrtc` daemon** hosted in
this repository.

## In one sentence

Everything you create or configure stays on your device. The only data that
ever leaves it is the WireGuard tunnel traffic you yourself directed there,
plus brief, end-to-end-encrypted signaling messages that the application
forwards through whichever signaling broker you have configured — which is
intended to be one you run yourself.

## What this means in practice

- **No analytics, telemetry, or crash reporting.** The app does not phone
  home. There is no developer-side server collecting data about you.
- **Local-only storage.** WireGuard keys, tunnel configurations, peer
  records, and application preferences live in the app's private
  storage and never leave the device except as part of an explicit
  user-initiated action (for example, backing up the device, or sharing a
  generated enrollment payload with another peer).
- **No third-party data sharing.** The application does not send data to
  advertisers, analytics services, cloud back-ends, or any other party.

## Signaling

To establish a tunnel between two peers behind NAT, the application briefly
exchanges metadata with a signaling broker that you configure. The broker
performs no role beyond forwarding messages between the participating peers.
The intended deployment is a broker you run yourself; a public broker may be
used as a default but you can replace it in the application's settings.

What the broker can see:

- your IP address (necessarily, since you are connected to it),
- routing identifiers derived from peer public keys (the broker does not
  see the keys themselves), and
- end-to-end-encrypted payloads it cannot decrypt — the encryption keys are
  derived from a Diffie-Hellman exchange over your WireGuard key material,
  to which the broker never has access.

The broker cannot read your tunnel traffic, your configuration, the identity
of your peers, or anything else about your device. Once a tunnel is
established, no further signaling traffic flows.

## Permissions

The application requests only the Android permissions it needs to operate as
a WireGuard client: `INTERNET`, foreground-service notification permissions,
`BIND_VPN_SERVICE` (via Android's `VpnService`, only invoked when you
activate a tunnel), and `CAMERA` (only when you tap "Scan QR code" during
enrollment; the camera is active only while that screen is open and no images
are stored).

## Open-source verification

Both the Android client and the `wireguardrtc` daemon are open-source under
the Apache License 2.0. The behaviors described above can be verified
against the source in this repository — `android/` for the app, `daemon/`
for the server-side daemon.

## Contact

Questions or concerns may be sent to
**`gutschke@users.noreply.github.com`** or filed as an issue on this
repository.
