# Comprehensive Guide to Dynamic WireGuard NAT Hole Punching

## 1. Overview
This document describes a Python daemon that maintains direct WireGuard tunnels between peers behind cone NATs without kernel modifications, eBPF, or userspace WireGuard. It also keeps endpoints fresh for peers reachable via dynamic DNS hostnames.

The daemon is non-destructive (it reads live kernel state via `wg show` and never parses `wg-quick` `.conf` files), single-file (deployed to `/usr/sbin/wireguardrtc`), and designed to be a good citizen on any PeerJS signaling broker (one shared connection, end-to-end encrypted signaling, untrusted-broker threat model).

## 2. Theory of Operation

WireGuard is a stateless UDP protocol. When both peers sit behind stateful NAT, neither can receive an unprompted handshake — a chicken-and-egg problem. The daemon resolves it through four phases:

1. **External Discovery (STUN).** The daemon queries public STUN servers to learn its public IPv4 address. Source IPs are resolved fresh per attempt to avoid stale DNS.
2. **Out-of-Band Signaling (PeerJS).** The discovered `(public_ip, listen_port)` is encrypted end-to-end and sent to the remote peer through a PeerJS WebSocket broker. The broker is treated as hostile public infrastructure.
3. **Active Hole Punching (Raw UDP Inject).** When the daemon learns the peer's public endpoint, it constructs a raw IP+UDP packet with `src_port = wg_listen_port` and sends it via `AF_INET / SOCK_RAW`. This bypasses the kernel-WG module's exclusive bind on that port and creates a NAT pinhole that the peer's eventual WireGuard handshake will traverse.
4. **Active Waking.** Immediately after the inject, the daemon writes the new endpoint via `wg set ... endpoint` and forces the kernel to dispatch a handshake by pushing a single byte through the WG interface (via `SO_BINDTODEVICE`). This minimises the window where the conntrack pinhole could expire (default UDP timeout: 30 s) before WG itself uses it.

Each step has been validated empirically — see [tests/](tests/) for the harness.

## 3. Cryptographic Design

### 3.1 Routing IDs
Each peer's PeerJS-broker ID is derived deterministically:
```
ID = Hex(SHA-256(PublicKey ‖ Salt))
```
Both endpoints share `Salt`, so each can compute the other's routing ID without out-of-band coordination. The salt prevents a broker observer from enumerating WireGuard public keys from IDs alone.

### 3.2 Payload Encryption (Domain-Separated)
The encrypted payload contains the local public IPv4 endpoint plus a UTC timestamp and protocol version. The flow is:
1. **ECDH:** `shared = X25519(local_wg_priv, peer_wg_pub)`.
2. **Key derivation:** `key = BLAKE2b(shared, key="wg-peerjs/v1/sigbox", 32 bytes)`.
3. **AEAD:** `ciphertext = SecretBox_XSalsa20_Poly1305(key).encrypt(payload)`.

Step 2 provides domain separation: the symmetric key cannot be reused as input to any other protocol. WireGuard's own Noise handshake uses an entirely separate key schedule; the daemon never feeds raw private keys into NaCl Box.

The payload includes `{v: 1, ts: <unix>, ip: <addr>, port: <int>}`. The receiver rejects anything older than ±90 s (replay window).

### 3.3 PeerJS Wire Format
The daemon wraps every signaling message in a WebRTC OFFER-shaped JSON envelope to maximise compatibility with PeerJS broker implementations:

```json
{
  "type": "OFFER",
  "dst": "<routing_id>",
  "payload": {
    "sdp":   {"sdp": "v=0\r\no=- ... a=ice-ufrag:... a=ice-pwd:... a=fingerprint:sha-256 ...\r\n",
              "type": "offer"},
    "type": "data",
    "connectionId": "dc_<random>",
    "label": "dc_<random>",
    "reliable": false,
    "serialization": "binary",
    "metadata": {"v": 1, "kind": "<optional>", "blob": "<base64 ciphertext>"}
  }
}
```

The SDP follows the standard PeerJS datachannel OFFER format with freshly generated ICE credentials per message. The encrypted blob travels in `metadata.blob` alongside the standard WebRTC fields. This envelope is used unconditionally — with all broker types — so there is one wire format.

The `metadata.kind` field discriminates between three message families:

| `kind`            | Meaning                                                                                       |
|-------------------|-----------------------------------------------------------------------------------------------|
| absent / `"offer"` | Ordinary signalling OFFER carrying a candidate-endpoint list.                                |
| `"signal_wake"`   | Client-initiated wake — sender claims no endpoint, asks the receiver to refresh its view.    |
| `"enroll"`        | Auto-enrollment request from a fresh client (see §5.4).                                       |
| `"enroll_ok"` / `"enroll_err"` | Server's response to an `enroll`.                                                |

The decrypted blob plaintext (after secretbox-decrypt) is JSON of this shape:

```json
{
  "v": 1, "ts": <epoch_seconds>,
  "candidates": [
    {"ip": "192.168.43.1", "port": 51820, "kind": "lan"},
    {"ip": "1.2.3.4",      "port": 51820, "kind": "stun"}
  ]
}
```

Senders list candidate endpoints in preference order. A phone in host-mode-on-hotspot fills `[LAN, STUN]` so on-LAN guests pick the LAN candidate without bouncing through the public IP (avoiding the cellular hairpin-NAT trap). An ordinary single-endpoint daemon fills exactly one entry. Senders that don't claim any endpoint (`signal_wake`) fill an empty list. Receivers take the first candidate that passes endpoint validation (`is_valid_public_endpoint`); kernel WireGuard's endpoint roaming picks up the rest from real handshake traffic, so the receiver doesn't time-share between candidates. The per-candidate `kind` is informational (`lan` / `stun` / `dns` / `manual`) — receivers don't interpret it.

### 3.4 Network Stack Injection
The kernel WireGuard module exclusively binds its UDP listen port (verified — userspace cannot share it via `SO_REUSEADDR`/`SO_REUSEPORT`). The daemon therefore constructs the IP and UDP headers in userspace and sends via `IP_HDRINCL` raw socket. The packet has source IP `0.0.0.0` (kernel fills from routing) and an empty UDP payload. Kernel netfilter / NAT processes it normally and creates a conntrack entry, which is then reused by the kernel WG module's outbound handshake.

## 4. Configuration

### 4.1 Generate the Salt
```bash
head -c 32 /dev/urandom | base64
```
Distribute the same salt to every endpoint that needs to find each other.

### 4.2 Global Configuration `/etc/wireguardrtc/wireguardrtc.conf`

```ini
[Global]
Salt = <base64 from above>

# Self-host a PeerJS broker (recommended):
#   docker run -d --name peerjs-broker --restart=always \
#       -p 9000:9000 peerjs/peerjs-server --port 9000 --key YOUR_SECRET_KEY
PeerJsServer = ws://your.broker.example:9000/peerjs
PeerJsKey = YOUR_SECRET_KEY

# Optional: skip STUN discovery on hosts with a known stable public IPv4.
# Useful for VPS deployments, dedicated-IP setups, or when outbound STUN
# is firewalled.  IPv4 only.
# PublicIp = 203.0.113.5

[Stun]
# Ignored when [Global] PublicIp is set.
Servers = stun.l.google.com:19302, stun.cloudflare.com:3478
```

Self-hosting a broker is recommended for production use. The broker sees only SHA-256 routing IDs and ciphertext, so it cannot read endpoint addresses, but a self-hosted instance avoids rate limits and gives you full control over availability.

#### `PublicIp` vs. STUN

`PublicIp` is the right choice when *exactly one* of these is true:

- The host has a static, known public IPv4 address (most VPS providers,
  dedicated-IP residential connections, anycast-fronted servers).
- The host runs in an isolated network where outbound STUN is blocked
  but the WireGuard listen port is reachable from outside.
- You're running tests or development inside a fabric / lab environment
  with no internet egress to a public STUN server.

For most home-router-NAT deployments, leave `PublicIp` unset and let STUN
discover the dynamic outbound IP. The daemon's existing handling of IP
changes (signalling new endpoints when STUN reports a different address)
covers ISP-renumbering and lease-renewal cases automatically.

`PublicIp` accepts a *single* IPv4 address. Multi-IP hosts must pick one
for the daemon to advertise; routing/firewall rules at the network layer
handle traffic on other addresses independently. List/array support and
IPv6 publication are deliberately out of scope: WireGuard's `endpoint`
field accepts only one `(ip, port)` tuple, and the v1 PeerJS wire format
carries one `ip` field — adding more would require a v2 protocol break.

### 4.3 Per-Peer Drop-Ins `/etc/wireguardrtc/peers.d/<label>.conf`
The daemon does NOT enumerate WireGuard peers automatically. Each peer that should be managed needs a drop-in file. Filename is a human-friendly label (use the peer's hostname, role, or anything you'll recognize); the actual public key is given inside.

```ini
# /etc/wireguardrtc/peers.d/laptop-anna.conf
[Peer]
PublicKey = <base64 of the peer's public key>
Mode = active
```

`Mode` is one of:

- `active` — the daemon proactively monitors the tunnel and sends OFFERs when it detects the peer is down, with exponential backoff from 30 s to 300 s. It also responds to incoming OFFERs when the tunnel is dead, so active-active pairs bootstrap in seconds rather than waiting for a full backoff cycle. Use for server-to-server tunnels and any peer expected to be persistently reachable.
- `passive` — the daemon never initiates outbound OFFERs for this peer, but responds to incoming OFFERs when the tunnel is down by advertising its own current endpoint. This lets clients behind restricted-cone NAT complete a mutual hole-punch. Use for mobile devices or clients that should initiate the session themselves.
- `dns-roam` — endpoint is updated from a DNS hostname; no PeerJS involvement. Add a `DnsHost = home.example.com:51820` line.
- `ignore` — daemon does nothing for this peer (useful for upstream client tunnels where the endpoint is static and managed externally).

Peers in `wg show` for which no drop-in file exists are treated as `ignore`.

A typical server with many client peers will have one `passive` drop-in for each client it expects to receive connections from. The server listens on PeerJS and responds to each client's OFFER with its own endpoint. Mobile clients need only send a single OFFER; the server's response gives them the server's current IP:port so both NATs can be punched simultaneously. Use `active` for peers the server itself wants to reach proactively.

#### Auto-active drop-ins for enrolled peers

When `[Enrollment] AutoActive = yes` (default), every successful ENROLL writes a drop-in to `<StateDir>/auto-enrolled.d/<label>-<fingerprint>.conf` with `Mode = active`. The daemon merges this directory with the admin-authored `/etc/wireguardrtc/peers.d/`, with admin entries winning on `PublicKey` collision. This is what lets the Phase-2 long-lived listener on the wireguardrtc-android client follow the server's STUN-discovered IP as it roams — without it, the daemon has no record of the new client and never pushes OFFERs to it.

Two reasons you might disable this:

- You manually curate `peers.d/` for every peer (e.g. you want explicit `Mode = passive` per client). Set `[Enrollment] AutoActive = no` and write the drop-ins yourself.
- You enroll a transient device and don't want the daemon to keep heartbeating to its routing-id forever. Either set `AutoActive = no`, or delete the auto-active drop-in once the device is decommissioned: `rm /var/lib/wireguardrtc/auto-enrolled.d/<label>-*.conf` (and reload the daemon, or wait for its next poll which re-reads peer configs after each enroll).

### 4.4 WireGuard Interface Configuration

wireguardrtc works alongside a normal WireGuard setup. Both hosts need WireGuard
configured first. For a general introduction see the
[WireGuard quickstart](https://www.wireguard.com/quickstart/) or `man wg-quick`.

Two requirements beyond a standard WireGuard config:

- **`ListenPort` must be static.** wireguardrtc advertises this port to the
  remote peer. An ephemeral port (no `ListenPort` set) changes on every restart
  and makes hole-punching unreliable.
- **Omit `Endpoint` in the `[Peer]` block.** wireguardrtc fills it in
  dynamically. Hardcoding an endpoint here will be overwritten by the daemon
  anyway and may cause confusion.

```ini
[Interface]
PrivateKey = <this host's private key>
Address    = 10.0.0.1/24
ListenPort = 51820            # must be a fixed port

[Peer]
PublicKey           = <the OTHER host's WireGuard public key>
AllowedIPs          = 10.0.0.2/32
PersistentKeepalive = 25
# No Endpoint — wireguardrtc sets this dynamically
```

Notes:

- `PersistentKeepalive = 25` is far more important than the daemon for day-to-day
  stability — a healthy keepalive keeps the NAT mapping alive without
  intervention. The daemon handles the cases where keepalive is not enough: peer
  was offline, NAT mapping expired, or the IP changed.
- An IPv4 host route in `AllowedIPs` lets the daemon force a handshake by writing
  a single byte through the WG interface to that IP. For `0.0.0.0/0` catchall
  configurations, the daemon uses `192.0.2.1` (TEST-NET-1) as the trigger
  destination instead.

## 5. Examples

### 5.1 Two NATed Hosts Find Each Other
Both hosts behind cone NATs, each listing the other in their `peers.d/` with `Mode = active`. When the tunnel goes idle, both daemons detect the outage within one poll cycle (30 s) and send OFFERs. The first OFFER to arrive triggers a response from the other side; both NATs are punched concurrently and the WireGuard handshake fires within a few seconds of the first OFFER.

### 5.2 Static VPS to Dynamic-DNS Home
The VPS configures the home peer with `Mode = dns-roam` and `DnsHost = home.example.com:51820`. The daemon resolves the hostname every 30 s and updates the kernel endpoint when it changes; PeerJS is not involved for this peer.

### 5.3 Server Behind NAT with Multiple Clients
A server behind a cone NAT configures each expected client with `Mode = passive`. When a client comes online it sends an OFFER via PeerJS. The server's daemon responds immediately with its own current endpoint. Both sides perform a raw UDP inject and trigger a handshake — the mutual hole-punch works even if both peers are behind port-restricted cone NATs. The server never initiates outbound OFFERs to clients; clients initiate contact and the server responds.

### 5.4 Auto-Enrollment (QR-Driven Pairing)
Instead of pre-sharing each peer's public key, the admin enables auto-enrollment in `wireguardrtc.conf`:

```ini
[Enrollment]
Enabled = yes
ProvisionScript = /usr/sbin/wireguardrtc-provision-default
```

To onboard a new peer, the admin mints a single-use voucher:

```sh
sudo wireguardrtc --enroll-token "Anna's Phone"
```

The command prints a `wgrtc-enroll://v1?...` URI (and a terminal QR code if `qrencode` is installed). The admin shares the QR with the user — by printing it, projecting it, or any other one-shot channel.

The user's client (e.g., a companion `wireguardrtc-android` app, or any third-party client that speaks the protocol) scans the QR, generates its own X25519 keypair, and sends an encrypted `ENROLL` request to the server via PeerJS. The server tries each pending token, decrypts on the matching one, atomically marks it consumed, runs `ProvisionScript` to add the new peer to WireGuard, reads back the allocated address via `wg show`, and responds with an authenticated `ENROLL_OK` carrying the client's WireGuard config.

The protocol is single-use: only one device can complete enrollment per token. If a QR is leaked and an attacker enrolls first, the legitimate user receives an authenticated `TOKEN_USED` response and the failure surfaces clearly — see the man page's AUTO-ENROLLMENT section for the full threat model. The man page also documents the `wgrtc-enroll://v1?...` URI format and the on-the-wire ENROLL/ENROLL_OK envelope; these are the spec for client implementations.

## 6. Compatibility Matrix (NAT)

| Local NAT | Peer NAT | Daemon outcome |
|---|---|---|
| Full / restricted / port-restricted cone, **port-preserving** | same | works |
| Cone but **non-port-preserving** | any | the published port is wrong; needs PCP/UPnP fallback (planned) or manual port-forwarding |
| Symmetric | any | direct P2P is mathematically impossible; relay (TURN / VPS) required |

Run `tests/01_stun_nat.py` to classify your NAT before deployment.

## 7. Operations

- Start: `systemctl enable --now wireguardrtc.service`
- Logs: `journalctl -fu wireguardrtc` — output is anti-spam (only state transitions are logged).
- Privileges: `CAP_NET_ADMIN` (read/write WG state via netlink) + `CAP_NET_RAW` (raw socket injection, `SO_BINDTODEVICE`). The systemd unit grants exactly these and drops everything else; running as root is supported but unnecessary.
- Concurrent tunnels / interfaces: discovered via `wg show interfaces` at every poll, no static interface list.
- Re-read configs without daemon restart: send `SIGHUP` (planned).

## 8. Limitations

- **IPv6 hole punching is not implemented.** The raw-inject builder constructs IPv4 headers only. Endpoint *publication* over v6 is in scope for a future phase — when both peers have global v6, NAT punching is unnecessary, but the daemon still doesn't take that fast path yet. (`tests/06_ipv6_path.py` reports v6 readiness.)
- **Symmetric-to-anything is out of scope** (mathematical limit of UDP hole punching).
- **PeerJS is the signaling channel.** Other relays (e.g., XMPP, Matrix) are not implemented. The encrypted-blob format is small enough to ride on most generic message buses if anyone wants to add another.

## 9. Debugging

- Tunnel never comes up after deploying the daemon: check `journalctl -fu wireguardrtc` for "STUN failed" or "decryption failed". Verify both peers share the exact same `Salt`.
- Hole-punch packet visible on neither end: `sudo tcpdump -i any udp port <listen_port>` while restarting the daemon. If you see no outbound packet, raw-socket capability is missing.
- PeerJS broker drops the connection: run `tests/05_peerjs.py` to isolate wire-format or connectivity issues against your broker.
- Peer endpoint set but tunnel still dead: the wake step probably failed. For peers with `0.0.0.0/0` allowed-ips the daemon waits up to 1 s for the kernel handshake; if you see endpoint updates but no traffic, run `tests/07_wake_observe.py`.

## 10. Additional Resources

- WireGuard whitepaper: https://www.wireguard.com/papers/wireguard.pdf
- PeerJS server: https://github.com/peers/peerjs-server
- RFC 5389 (STUN): https://datatracker.ietf.org/doc/html/rfc5389
- libsodium / NaCl: https://doc.libsodium.org/
