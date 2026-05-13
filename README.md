# wgrtc

WireGuard tunnels that find their way home through NAT and roaming IPs.

This repository hosts the two pieces of the wgrtc system:

| Component | Where | What it is |
|---|---|---|
| **Daemon** | [`daemon/`](daemon/) | A Linux daemon that exchanges encrypted endpoint addresses with remote peers through a signaling broker, then punches both NATs open so the kernel WireGuard module can complete its handshake. Single-file Python 3 asyncio. Ships as a Debian package. |
| **Android app** | [`android/`](android/) | A WireGuard tunnel manager for Android, including Chromebooks that support Android apps. Implements the same signaling protocol as the daemon, plus extensions for phone-to-phone use: SAS-based wormhole enrollment, host-mode tunnels, NAT-traversal helpers in a userspace `gvisor` netstack. |

Both components speak the same wire format. A phone can join a tunnel hosted by a server running the daemon, or two phones can host each other — no central infrastructure required beyond a signaling broker, which you can run yourself.

## Quick tour

- **What problem we solve.** WireGuard is a stateless UDP protocol. When both peers sit behind NAT, neither can initiate a handshake until it knows the other's current public endpoint. We solve this for cone NATs (full-cone, address-restricted, port-restricted) by exchanging endpoint addresses through a small WebSocket broker, end-to-end-encrypted with keys derived from each side's existing WireGuard identity. After exchange, both sides simultaneously punch their NATs open with a raw UDP packet from the WireGuard listen port; the next handshake then completes through both states.
- **What the broker can see.** SHA-256 routing IDs and ciphertext. Endpoints are encrypted with XSalsa20-Poly1305 using a key derived from a Curve25519 Diffie-Hellman over the WireGuard key material; the broker cannot read or forge them. Self-hosting the broker is strongly recommended for anything beyond ad-hoc testing.
- **What ships in this repo.** No central servers, no user accounts, no telemetry. The Android app's privacy policy is at [`PRIVACY.md`](PRIVACY.md).

For the cryptographic and protocol details, see [`docs/wg-holepunch-guide.md`](docs/wg-holepunch-guide.md).

## Where to go from here

- Setting up a server? Start at [`daemon/README.md`](daemon/README.md).
- Building or installing the Android app? Start at [`android/README.md`](android/README.md).
- Curious how it works under the hood? [`docs/wg-holepunch-guide.md`](docs/wg-holepunch-guide.md) is the authoritative design doc.
- Releasing a new version? [`RELEASING.md`](RELEASING.md).
- Contributing? [`CONTRIBUTING.md`](CONTRIBUTING.md).

## NAT compatibility

| NAT type | Result |
|---|---|
| Full-cone / address-restricted / port-restricted, **port-preserving** | Works |
| Cone NAT, **non-port-preserving** | Fails (needs NAT-PMP/PCP or manual port forward) |
| Symmetric | Mathematically impossible without a relay |

Run [`daemon/tests/01_stun_nat.py`](daemon/tests/01_stun_nat.py) against your network to classify it.

## License

Licensed under the [Apache License 2.0](LICENSE).

Third-party components shipped or linked from this repository retain their own licenses; see [`NOTICE`](NOTICE) and [`THIRD_PARTY_LICENSES/`](THIRD_PARTY_LICENSES/) for the full attribution list.

WireGuard is a registered trademark of Jason A. Donenfeld.
