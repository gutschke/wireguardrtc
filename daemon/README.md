# wireguardrtc

A lightweight daemon that maintains direct WireGuard tunnels between peers behind
NAT — without static IPs, relay servers, or kernel modifications.

> **The daemon and the Android app speak the same wire format.** Anything below
> works for daemon-to-daemon (typical site-to-site), but the remote peer can
> equally well be the [Android app](../android/) — e.g. your phone joining a
> tunnel hosted by this daemon, or this daemon joining a tunnel hosted by the
> Android app on someone else's phone. Mix and match.

## Configuration checklist — every place you have to touch

First-run pitfalls cluster around forgotten settings. Before reporting that
"the tunnel won't come up", verify every item on this list on **both** sides:

| # | File / setting | What | Where it's documented |
|---|---|---|---|
| 1 | `wg0.conf` `ListenPort` | Must be a **fixed** port, not ephemeral | [WireGuard configuration](#wireguard-configuration) |
| 2 | `wg0.conf` `[Peer] Endpoint` | Must be **absent** — the daemon fills it in | [WireGuard configuration](#wireguard-configuration) |
| 3 | `/etc/wireguardrtc/wireguardrtc.conf` `[Global] Salt` | **Must be byte-identical on every host in the mesh.** Generate once with `head -c 32 /dev/urandom \| base64`, then copy. This is the most-missed step. | [Quick start §1](#1-generate-a-shared-salt) |
| 4 | `[Global] PeerJsServer` + `PeerJsKey` | Signaling broker. Self-host recommended; public broker at `0.peerjs.com` works for testing. | [Signaling server](#signaling-server) |
| 5 | `/etc/wireguardrtc/peers.d/<label>.conf` | One drop-in per remote peer, carrying the **remote** peer's WG `PublicKey` and a `Mode` (active / passive / dns-roam / ignore). No drop-in → daemon ignores. | [Quick start §3](#3-add-a-peer-drop-in-for-each-remote-host) |
| 6 | `[Enrollment]` section (optional) | Only needed if you want phones / new daemons to enroll via QR code instead of hand-edited `peers.d/`. | [Auto-enrollment](#auto-enrollment-optional) |
| 7 | `/etc/wireguardrtc/provision-broker.conf` | Companion to §6 — which Provisioner the privileged broker should call. | [Auto-enrollment](#auto-enrollment-optional) |

After editing any of the above, `sudo wireguardrtc --show-config` is the
canonical sanity check: the `salt-fingerprint` line must match on both peers,
and each side's `THIS PEER broker-id` must equal the other side's record of
the same peer.

## Problem

WireGuard is a stateless UDP protocol. When both peers sit behind NAT, neither
can initiate a handshake until it knows the other's current public endpoint
(`ip:port`). Keepalives help once a tunnel is established, but they can't
bootstrap from scratch or recover after both sides restart simultaneously.

`wireguardrtc` solves this for cone NATs (full-cone, address-restricted,
port-restricted) by using a signaling server to exchange encrypted endpoint
addresses, followed by simultaneous raw UDP injection to punch both NATs open
before the WireGuard handshake fires.

## How it works

1. **STUN** — discover your public IPv4 address via STUN (or skip STUN by
   configuring `[Global] PublicIp` if you have a known static address)
2. **Signal** — exchange endpoint info with your peer through a PeerJS WebSocket
   broker, encrypted end-to-end with keys derived from your WireGuard identities
3. **Punch** — inject a raw UDP packet from your WireGuard listen port to create
   a conntrack entry through your NAT
4. **Wake** — update the kernel WireGuard endpoint and trigger an immediate handshake

The broker sees only SHA-256 routing IDs and ciphertext. Endpoint addresses are
encrypted with XSalsa20-Poly1305 using a key derived from a Curve25519
Diffie-Hellman over your existing WireGuard key material; the broker cannot
read or forge them.

For full cryptographic and protocol details see [`../docs/../docs/wg-holepunch-guide.md`](../docs/wg-holepunch-guide.md).

## NAT compatibility

| NAT type | Result |
|---|---|
| Full-cone / address-restricted / port-restricted, **port-preserving** | Works |
| Cone NAT, **non-port-preserving** | Fails (needs NAT-PMP/PCP or port forward) |
| Symmetric | Mathematically impossible without relay |

Run `tests/01_stun_nat.py` to classify your NAT before deploying.

## Requirements

- Linux with kernel WireGuard (`wireguard-tools`)
- Python 3.10+, `python3-venv`
- `CAP_NET_ADMIN` + `CAP_NET_RAW` (the systemd unit requests exactly these)
- A PeerJS signaling server reachable by all participating peers

## Signaling server

**Self-hosting is strongly recommended** for anything beyond ad-hoc testing.
The broker sees only SHA-256 routing IDs and ciphertext, but a self-hosted
instance avoids rate limits and gives you full control over availability.

```sh
docker run -d --name peerjs-broker --restart=always \
    -p 9000:9000 \
    peerjs/peerjs-server --port 9000 --key YOUR_SECRET_KEY
```

Set in `/etc/wireguardrtc/wireguardrtc.conf`:
```ini
PeerJsServer = ws://your.broker.example:9000/peerjs
PeerJsKey = YOUR_SECRET_KEY
```

The public broker at `0.peerjs.com` works for testing and very small setups
but is subject to rate limiting and connection caps. See
[peerjs-server](https://github.com/peers/peerjs-server) for self-hosting
options including TLS and multiple key support.

## Installation

### Debian / Ubuntu package (recommended)

```sh
sudo dpkg -i wireguardrtc_0.1.0-1_all.deb
sudo apt-get install -f    # resolve dependencies if needed
```

The package installs the daemon, man page, and example configuration.
It creates a `wireguardrtc` system user and builds a Python venv at install
time — **an internet connection is required during `dpkg -i`.**

Build the package from source with:
```sh
dpkg-buildpackage -us -uc -b
```

### From source

```sh
python3 -m venv venv
venv/bin/pip install -r requirements.txt
sudo venv/bin/python3 ./wireguardrtc
```

## WireGuard configuration

wireguardrtc works alongside a normal WireGuard setup — it does not replace it.
Both hosts need WireGuard installed and configured first.
If you are new to WireGuard, start with the [official quickstart](https://www.wireguard.com/quickstart/) or `man wg-quick`.

Two requirements beyond a standard WireGuard config:

- **Static `ListenPort`** — wireguardrtc advertises this port to the remote peer.
  If the port is ephemeral (no `ListenPort` set), it changes on every restart and
  hole-punching stops working.
- **No `Endpoint`** — leave the `Endpoint` line out of the `[Peer]` block.
  wireguardrtc fills it in dynamically once the remote peer's address is known.

Minimal `/etc/wireguard/wg0.conf` on **each host**:

```ini
[Interface]
PrivateKey = <this host's private key>
Address    = 10.0.0.1/24    # pick addresses on a private subnet
ListenPort = 51820          # must be a fixed port

[Peer]
PublicKey           = <the OTHER host's WireGuard public key>
AllowedIPs          = 10.0.0.2/32
PersistentKeepalive = 25
# No Endpoint — wireguardrtc sets this dynamically
```

Generate a keypair with:
```sh
wg genkey | tee /etc/wireguard/wg0.key | wg pubkey > /etc/wireguard/wg0.pub
chmod 600 /etc/wireguard/wg0.key
```

Enable WireGuard: `sudo systemctl enable --now wg-quick@wg0`

## Quick start

### 1. Generate a shared salt

The salt derives the routing IDs peers use to find each other on the broker.
Generate once and copy the **same value** to every host in the mesh:

```sh
head -c 32 /dev/urandom | base64
```

### 2. Configure the daemon

```sh
sudo nano /etc/wireguardrtc/wireguardrtc.conf
# Set: Salt, PeerJsServer, PeerJsKey
```

### 3. Add a peer drop-in for each remote host

Each drop-in file tells the daemon about **one remote peer** using that peer's
WireGuard public key — the same key that appears in the `[Peer]` block of your
`wg0.conf`. The daemon discovers its own identity from the running kernel; you
never put the local host's key in a drop-in.

```sh
sudo cp /usr/share/doc/wireguardrtc/examples/peers.d/active-peer.conf \
        /etc/wireguardrtc/peers.d/my-peer.conf
sudo nano /etc/wireguardrtc/peers.d/my-peer.conf   # set PublicKey to the REMOTE host's key
```

Do the same on the remote host, pointing at this host's public key.

### 4. Verify both sides agree

Run on **both** hosts and compare:

```sh
sudo wireguardrtc --show-config
```

The `salt-fingerprint` must match on both sides. The broker-id shown under
`THIS PEER` on host A must equal the broker-id shown for that peer entry on
host B, and vice versa. If they match, the daemon can find the remote peer on
the signaling broker.

### 5. Start and watch

```sh
sudo systemctl enable --now wireguardrtc
journalctl -fu wireguardrtc
```

Within a few seconds you should see `tunnel UP` in the log and
`wg show wg0 latest-handshakes` should show a recent timestamp.

## Peer modes

| Mode | Behavior |
|---|---|
| `active` | Proactively signals when tunnel is dead; also responds to incoming OFFERs so active-active pairs bootstrap in seconds |
| `passive` | Never initiates outbound signals, but responds to incoming OFFERs with this host's own endpoint so clients can complete a mutual hole-punch |
| `dns-roam` | Tracks endpoint via DNS hostname (`DnsHost = host:port`); no PeerJS |
| `ignore` | Daemon ignores this peer entirely |

Peers present in `wg show` but without a drop-in file are treated as `ignore`.

Both `active` and `passive` peers respond to incoming OFFERs when the tunnel
is down. The difference is only whether the daemon ever *initiates* an OFFER
unprompted: `active` does, `passive` waits for the remote end to go first.

## Auto-enrollment (optional)

Auto-enrollment lets a new device join the mesh by scanning a single QR code,
without anyone manually exchanging public keys. The user generates their own
keypair on-device, sends the public half to the server inside an encrypted
ENROLL message keyed off a single-use token, and the server responds with the
allocated address and endpoint info — all over the same PeerJS broker the
daemon already uses for hole-punching. The `wireguardrtc-android` client
implements this; any other client speaking the protocol works too.

To enable, on the server:

1. Pick the upstream Provisioner that fits your deployment. The daemon does
   **not** invoke it directly — it runs sandboxed and routes the request
   through `wireguardrtc-provision-broker`, a small privileged helper started
   on demand via systemd socket activation. Two Provisioners ship with the
   package:

   - `/usr/sbin/wireguardrtc-provision-default` — for stock `wg-quick`
     deployments. Allocates from a CIDR pool defined in
     `/etc/wireguardrtc/provisioning.conf` and appends `[Peer]` blocks to
     `/etc/wireguard/<iface>.conf`.

     ```sh
     sudo cp /usr/share/doc/wireguardrtc/examples/provisioning.conf.example \
             /etc/wireguardrtc/provisioning.conf
     sudo nano /etc/wireguardrtc/provisioning.conf   # set Pool = ...
     ```

   - Your own helper for custom WireGuard tooling (Ansible, the `add-peer`
     family, etc.). The script-level contract is `IFACE NAME PUBKEY_BASE64`
     and is documented in
     [`man wireguardrtc(8)`](wireguardrtc.8) under `[Enrollment]`.

   Tell the broker which Provisioner to use:

   ```sh
   sudo cp /usr/share/doc/wireguardrtc/examples/provision-broker.conf.example \
           /etc/wireguardrtc/provision-broker.conf
   sudo nano /etc/wireguardrtc/provision-broker.conf   # set Provisioner = ...
   ```

2. Enable the broker (socket-activated, no resident process):

   ```sh
   sudo systemctl enable --now wireguardrtc-provision-broker.socket
   ```

3. Enable enrollment in `/etc/wireguardrtc/wireguardrtc.conf`:

   ```ini
   [Enrollment]
   Enabled         = yes
   ProvisionScript = /usr/sbin/wireguardrtc-provision-client
   StateDir        = /var/lib/wireguardrtc
   MaxPendingTokens = 32
   ```

   `wireguardrtc-provision-client` is a thin daemon-side wrapper that talks
   to the broker over `/run/wireguardrtc-provision/sock`. Always point
   `ProvisionScript` at it, never directly at a helper that writes to
   `/etc/wireguard/` — the daemon's sandbox blocks that path on purpose.

4. Restart the daemon: `sudo systemctl restart wireguardrtc`.

5. Mint a token for each new peer:

   ```sh
   sudo wireguardrtc --enroll-token "Anna's Pixel 8" --expires 600
   ```

   This prints a `wgrtc-enroll://v1?…` URI and (when stdout is a TTY) a
   terminal QR code. Show that QR to the user — they scan it in the
   `wireguardrtc-android` app and tap Connect. The client sends ENROLL,
   the daemon validates the token, calls `ProvisionScript` to add the
   peer, and returns ENROLL_OK with the assigned address. Tunnel comes
   up immediately.

   The daemon also drops a small `peers.d`-style record for the new
   peer under `<StateDir>/auto-enrolled.d/` (default
   `/var/lib/wireguardrtc/auto-enrolled.d/`) so it will keep pushing
   signalling OFFERs to that peer as your server's STUN-discovered
   public IP roams — no `peers.d/` hand-authoring per enrolled
   client. Override per-peer by writing `/etc/wireguardrtc/peers.d/<name>.conf`
   with the same `PublicKey` (admin entries win on collision); disable
   the feature globally with `[Enrollment] AutoActive = no`. See
   `wireguardrtc(8)` and the holepunch guide for the merge rules.

The token is single-use: an attacker who steals the QR can race for it,
but the loser receives an authenticated `TOKEN_USED` response so the
legitimate user notices the failure rather than silently re-enrolling
onto a stolen identity. Treat QR images like one-time passwords (E2EE
channels or in person, not plaintext email).

### Roadmap: wormhole pairing

The Android app additionally supports **wormhole-style pairing** — two devices
exchange a six-letter shared secret, run SPAKE2 over the same broker, and
display a matching SAS confirmation phrase before completing the connection.
This is much friendlier than QR for **site-to-site setup** (where neither end
has a camera handy) and for retrofitting wgrtc onto an existing pair of
servers without copy-pasting WG keys by hand.

The daemon doesn't speak this protocol yet — it's tracked as task D1. Until
then, server-to-server provisioning uses either hand-edited `.peers` /
`peers.d/` files, or the QR-enrollment flow above (with the joiner side using
a wgrtc client app or the QR's plain-text URI).

Peer names accept Unicode letters and digits plus space, dot, apostrophe,
underscore, and hyphen — names like `Anna's Pixel 8` or `François's
Laptop` round-trip cleanly through the entire auto-enroll path.
Commas, slashes, and shell metacharacters are rejected.

**Privilege-separated provisioning.** The daemon sits at the open
internet (PeerJS WebSocket + WG endpoint), so its RCE blast radius is
the limiting factor. The package routes auto-enroll provisioning
through `wireguardrtc-provision-broker`, a small socket-activated root
helper, plus a single-use **permit** dropped by `--enroll-token` into a
directory the daemon cannot write to. The broker refuses to provision
unless a matching permit is present; outside the mint→consumption
window, a hypothetical daemon RCE has no provisioning capability at
all. Inside the window, an attacker can attempt to hijack the
in-flight enrollment but the legitimate user notices via `TOKEN_USED`.

**Privilege-separated key derivation, raw inject, and `wg set`.** The
daemon process runs with **zero Linux capabilities**. Each privileged
operation lives in a dedicated tiny sibling service:

- `wireguardrtc-key-oracle.service` — holds the WireGuard private keys
  and `CAP_NET_ADMIN`. Serves `derive_sigbox`, `derive_enroll`, and
  `set_endpoint` over `/run/wireguardrtc/oracle.sock`. Refuses to
  silently create new peers in `set_endpoint`. Raw private-key bytes
  never enter the daemon's address space.
- `wireguardrtc-raw-helper.service` — holds `CAP_NET_RAW`. Serves
  `inject` (the hole-punch burst with spoofed source port) and `wake`
  (the `SO_BINDTODEVICE`-bound handshake trigger) over
  `/run/wireguardrtc/raw.sock`. Refuses inject when the requested
  source port doesn't match the iface's actual WG listen-port, or
  when the destination IP fails the loopback/link-local/multicast
  check.
- `wireguardrtc-provision-broker` — holds whatever the configured
  Provisioner needs (typically `CAP_NET_ADMIN` for `wg-quick strip` /
  `wg syncconf`, or root for site-specific `add-peer` script families
  that mutate `/etc/wireguard/` directly).

After daemon RCE an attacker can issue narrow validated RPCs to the
helpers but cannot lift the raw WireGuard private key, cannot fire
arbitrary spoofed packets, and cannot mutate `/etc/wireguard/`. Same
privsep pattern OpenSSH uses for the SSH host key — the
network-facing process holds nothing valuable.

See `man wireguardrtc(8)` for the full design under
`SECURITY/Privilege model` and
`SECURITY/Auto-enrollment privilege separation`.

See `man wireguardrtc(8)` section `AUTO-ENROLLMENT` for the full
threat model, wire format, and URI grammar.

## Diagnostics

```sh
# Full configuration cross-check (broker IDs, handshake ages, peers.d status)
sudo wireguardrtc --show-config

# Limit to one interface
sudo wireguardrtc --show-config --iface wg0

# Live log (state transitions only — no noise)
journalctl -fu wireguardrtc
```

## License

[Apache License 2.0](../LICENSE) — source at https://github.com/gutschke/wgrtc
