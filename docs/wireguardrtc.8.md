<!-- generated from wireguardrtc.8 by build_man_md.py — do not edit by hand -->
# WIREGUARDRTC(8) — System Manager's Manual

## NAME

wireguardrtc - WireGuard NAT hole-punching daemon via PeerJS signalling

## SYNOPSIS

<b>wireguardrtc</b> \[--config FILE\] \[--peers-dir DIR\] \[--log-level LEVEL\]

<b>wireguardrtc</b> <b>--show-config</b> \[--iface IFACE\]

<b>wireguardrtc</b> <b>--enroll-token NAME</b> \[--expires SECONDS\] \[--iface IFACE\]

## DESCRIPTION

<b>wireguardrtc</b> maintains direct UDP tunnels between WireGuard peers that are located behind cone NATs (full-cone, address-restricted, or port-restricted). It does not require a VPN relay or any static public IP address on either end of the tunnel.

The daemon operates by:
- **1.**
  Discovering the host's current public IPv4 address via STUN.
- **2.**
  Encrypting that address (together with the WireGuard listen port and a freshness timestamp) using a key derived from the two endpoints' WireGuard Curve25519 identities.
- **3.**
  Delivering the encrypted blob to the remote peer through a <i>PeerJS</i> signalling broker, using the standard PeerJS OFFER wire format.
- **4.**
  Punching a NAT pinhole from the local WireGuard listen port toward the remote endpoint using a raw IP+UDP packet (source-port spoofed to the WG listen port).
- **5.**
  Waking the kernel WireGuard module by sending a datagram through the WG interface, causing it to initiate a handshake to the newly established endpoint.

Configuration is split between a single global file and per-peer drop-in files.  Peers without a drop-in file are silently ignored, allowing gradual adoption in mixed deployments.

The daemon is a single-file Python 3 asyncio program installed as <i>/usr/sbin/wireguardrtc</i>. It runs under systemd as the <b>wireguardrtc</b> system user with <b>CAP_NET_ADMIN</b> and <b>CAP_NET_RAW</b> capabilities; it does not require root.  Running as root is also supported.

## OPTIONS

- <b>--config</b><i> FILE</i>
  Path to the global configuration file.
  Default: <i>/etc/wireguardrtc/wireguardrtc.conf</i>
  Override with the environment variable <b>WIREGUARDRTC_CONFIG_DIR</b> (sets the directory; the filename <i>wireguardrtc.conf</i> is appended).

- <b>--peers-dir</b><i> DIR</i>
  Directory containing per-peer drop-in files (<i>*.conf</i>).
  Default: <i>/etc/wireguardrtc/peers.d</i>

- <b>--lock-file</b><i> PATH</i>
  Path to the single-instance lock file.
  Default: <i>/run/wireguardrtc/lock</i>
  Override with the environment variable <b>WIREGUARDRTC_LOCK_FILE</b>.
  The default path is created and owned by the systemd <b>RuntimeDirectory</b> mechanism when the unit is started; running the daemon manually as a non-systemd-managed user requires picking a writable path here.  This option is also useful for running multiple daemon instances on the same host (for testing or per-namespace deployments) — each instance must use a distinct lock path or they will refuse to start, citing <i>another wireguardrtc daemon already holds <path></i>.

- <b>--log-level</b><i> LEVEL</i>
  Logging verbosity.  One of <b>DEBUG</b>, <b>INFO</b>, <b>WARNING</b>, <b>ERROR</b>.
  Default: <b>INFO</b> (overridable with the environment variable <b>LOG_LEVEL</b>).

- <b>--show-config</b>
  Print this peer's WireGuard identity and PeerJS broker IDs, then exit.  For each configured peer, also prints a ready-to-paste <i>peers.d</i> drop-in that the remote host should use to point back at this one.

  Use this command on both peers to diagnose configuration mismatches: the <i>broker-id</i> shown under <b>THIS PEER</b> on host A must equal the <i>broker-id</i> shown for the corresponding peer entry on host B, and vice versa. If the broker IDs don't match despite a common <b>Salt</b> value, the <b>PublicKey</b> in one of the drop-in files is wrong.

This option does not start the daemon, does not acquire the lock file, and does not require <b>CAP_NET_RAW</b>. It does need <b>CAP_NET_ADMIN</b> (or root) to read WireGuard public keys from the kernel.

- <b>--iface</b><i> IFACE</i>
  Used together with <b>--show-config</b> or <b>--enroll-token</b>. Restrict operation to the single WireGuard interface named <i>IFACE</i>. For <b>--show-config</b>, without this option all WireGuard interfaces are shown. For <b>--enroll-token</b>, this option chooses which interface's public key is embedded in the generated URI; required when the host has multiple WireGuard interfaces.

Run <b>--show-config --iface wg0p4</b> on both ends and compare the output line by line to spot key or broker-id mismatches.

- <b>--enroll-token</b><i> NAME</i>
  Mint a single-use enrollment token for the peer named <i>NAME</i>, print the <b>wgrtc-enroll://v1?...</b> URI to standard output, render a terminal QR code if standard output is a TTY and <b>qrencode</b>(1) is installed, then exit.  See <b>AUTO-ENROLLMENT</b> below for details on the protocol and the URI format.

<b>Enrollment must be enabled</b> in <b>CONFIG_DIR</b>/wireguardrtc.conf under <b>[Enrollment]</b> <b>Enabled = yes</b>, with <b>ProvisionScript</b> pointing at an executable hook (see <b>--iface</b> and <b>[Enrollment]</b>).

- <b>--expires</b><i> SECONDS</i>
  Used together with <b>--enroll-token</b>. Token lifetime in seconds; valid range <b>60</b>..<b>604800</b> (1 minute to 7 days).
  Default: <b>600</b> (10 minutes).

## CONFIGURATION FILES

### Global configuration — wireguardrtc.conf

The global configuration file uses INI format (parsed by Python's <b>configparser</b>). Key names are case-sensitive; base64 values are preserved verbatim.

  <b>[Global]</b>

  - <b>Salt = *string*</b>
    <b>Required.</b> A site-specific random string shared by all hosts that participate in the same signalling domain.  The salt is incorporated into the PeerJS routing ID derivation; peers with different salts cannot find each other on the broker even if they share the same WireGuard public key.
    Both sides of every tunnel <i>must</i> use the same salt.
    Generate with:
  - 

```
head -c 32 /dev/urandom | base64
```

  - 
    The daemon refuses to start if Salt is absent or still set to the placeholder value <i>CHANGE_ME_TO_A_SECURE_RANDOM_STRING</i>.

  - <b>PeerJsServer = *wss://host/path*</b>
    WebSocket URL of the PeerJS signalling broker.
    Default: <i>wss://0.peerjs.com/peerjs</i> (the public PeerJS broker).
    For private deployments, self-host the <b>peerjs-server</b> Docker image and point this setting at <i>ws://your.host:9000/peerjs</i>.

  - <b>PeerJsKey = *string*</b>
    The PeerJS application key.  Must match the key configured on the broker.
    Default: <i>peerjs</i> (matches the public broker's default).

  - <b>PublicIp = *A.B.C.D*</b>
      <i>Optional.</i> A static IPv4 address that overrides STUN discovery.  When set, the daemon advertises this address in OFFERs without querying any STUN server.  Useful on:
      - 
        hosts with a known static public IPv4 (VPS, anycast, dedicated IP),
      - 
        isolated network segments where outbound STUN is firewalled,
      - 
      test fabrics where the host has no internet egress.
      - 
        The value must be a valid IPv4 address that is not loopback, multicast, link-local, unspecified, or otherwise reserved.  IPv6 endpoint publication is not implemented; use the underlying WireGuard configuration directly if you need an IPv6 endpoint.
      - 
      Default: unset (use STUN).

        <b>[Stun]</b>

        - <b>Servers = *host:port*[, *host:port* ...]</b>
          Comma-separated list of STUN server endpoints.  The daemon queries them in order and uses the first response.  Ignored when <b>PublicIp</b> is set in the <b>[Global]</b> section.
          Default: <i>stun.l.google.com:19302</i>, <i>stun.cloudflare.com:3478</i>, <i>stun.nextcloud.com:3478</i>

        - <b>Strict = *yes|no*</b>
          When <b>yes</b>, STUN responses whose XOR-MAPPED-ADDRESS is not globally routable (RFC 1918 private, CGN 100.64/10, loopback, link-local, RFC 5737 documentation, multicast, etc.) are rejected and the daemon tries the next server in the list.  Useful when you know the host has a real public IPv4 address and a hijacked or misconfigured STUN server would otherwise feed you an internal address that you'd advertise to peers as the host's endpoint.
        Default: <b>no</b> (LAN-only deployments legitimately advertise private addresses).

          <b>[Enrollment]</b> This section is read only when auto-enrollment is in use.  See the <b>AUTO-ENROLLMENT</b> section below for the full protocol description.  In a deployment that only uses pre-shared peer keys (the original v0.1 model), leave the section out entirely.

          - <b>Enabled = *yes|no*</b>
            Enable the auto-enrollment handler.  When <b>yes</b>, the daemon listens for <b>ENROLL</b> messages on its PeerJS connection and processes them via the configured <b>ProvisionScript</b>. When <b>no</b> (or absent), incoming <b>ENROLL</b> messages are silently dropped.
            Default: <b>no</b>

          - <b>ProvisionScript = *PATH*</b>
            Path to an executable that is invoked to add a newly-enrolled peer. The script is called as:
          - 

```
ProvisionScript IFACE NAME PUBKEY_BASE64
```

          - 
            and must exit <b>0</b> on success.  After a successful exit, the daemon reads back the peer's allocated address via <b>wg show *IFACE* allowed-ips</b>.
            <b>Required when Enabled = yes.</b>
          - 
              <b>Default and recommended value:</b> <i>/usr/sbin/wireguardrtc-provision-client</i>. This is a thin wrapper that hands the request to the privileged <b>wireguardrtc-provision-broker</b>(8) over a Unix socket; the broker then invokes the actual provisioning helper with root privileges.  The broker exists because the daemon runs heavily sandboxed (see <b>SECURITY</b> below) and cannot itself write to <i>/etc/wireguard</i> or run privileged tooling.  Configure which helper the broker invokes in <i>/etc/wireguardrtc/provision-broker.conf</i>; two helpers ship with this package:
              - 
                <i>/usr/sbin/wireguardrtc-provision-default</i> — allocates from a CIDR pool defined in <i>/etc/wireguardrtc/provisioning.conf</i> and writes a <b>[Peer]</b> block to <i>/etc/wireguard/IFACE.conf</i>.
              - 
              A custom helper of your own (Ansible-managed peers, the <i>add-peer</i>/<i>show-peer</i> helper-script family used by some private deployments, etc.).
              - 
                Do <b>not</b> point ProvisionScript directly at the helper unless you have also relaxed the daemon's sandbox to allow filesystem access — the default helpers all write to <i>/etc/wireguard/</i>, which the daemon's <b>ProtectSystem=strict</b> forbids.  See the <b>SECURITY</b> section below for the privilege-separation rationale.

              - <b>StateDir = *PATH*</b>
                Directory holding the daemon's persistent enrollment state, in particular the <i>pending-tokens.json</i> file.  The directory is created with mode <b>0700</b> on first use.
                Default: <i>/var/lib/wireguardrtc</i>.

              - <b>MaxPendingTokens = *N*</b>
                Refuse to mint additional tokens once <i>N</i> unconsumed tokens are already pending; admin must wait for them to be used or to expire.  Bounds worst-case state size and per-ENROLL decryption cost.
                Default: <b>32</b> (range <b>1</b>..<b>1000</b>).

              - <b>AutoActive = *yes*|*no*</b>
                When a peer completes enrollment, automatically write a peers.d-style drop-in for it to <i><StateDir>/auto-enrolled.d/</i>. The drop-in carries <b>Mode = active</b> so the daemon pushes signalling OFFERs (with the daemon's current STUN-discovered IPv4) to the new peer without requiring you to hand-author <i>/etc/wireguardrtc/peers.d/<label>.conf</i>. This is what lets the Phase-2 long-lived listener on the Android client follow your server's roaming public IP between sessions.
                An explicit drop-in in <i>/etc/wireguardrtc/peers.d/</i> with the same <b>PublicKey</b> always wins over the auto-active entry, so you can override any specific peer (e.g. downgrade to <b>passive</b> or <b>ignore</b>).
                Set this to <b>no</b> if you want strict admin opt-in for every peer's OFFER push.
              Default: <b>yes</b>.

### Per-peer drop-ins — peers.d/*.conf

Each file in the peers directory describes one remote WireGuard peer. The filename (without the <i>.conf</i> suffix) is used as a human-readable label in log output; it has no functional significance.  The actual peer identity comes from the <b>PublicKey</b> field inside the file.

Files are parsed with the same INI parser as the global config (case-sensitive keys).

  <b>[Peer]</b>

  - <b>PublicKey = *base64*</b>
    <b>Required.</b> The WireGuard public key of the remote peer, in standard base64 encoding.  The daemon matches this against the live kernel state returned by <b>wg show</b>.

  - <b>Mode = active | passive | dns-roam | ignore</b>
    Controls how the daemon behaves for this peer.
    Default: <b>passive</b> (if the field is absent or unrecognised).
    See <b>PEER MODES</b> below for a full description.

  - <b>DnsHost = *hostname:port*</b>
  Applicable only when <b>Mode = dns-roam.</b> The hostname is resolved to an IPv4 address every poll cycle; if the resolved address differs from the current WireGuard endpoint the kernel is updated with <b>wg set</b>. The daemon refuses to load a <b>dns-roam</b> peer that omits this field.

## PEER MODES

- <b>active</b>
<!-- TROFF sp  -->
<!-- TROFF sp  -->
<!-- TROFF sp  -->
  The daemon proactively monitors the tunnel.  Every poll cycle it reads <b>latest-handshakes</b> from the kernel; if the most recent handshake is older than <b>HANDSHAKE_DEAD_THRESHOLD</b> (180 seconds — the WireGuard rekey interval of 120 s plus a 60 s grace period) the tunnel is considered dead and the daemon sends a PeerJS OFFER carrying this host's current public endpoint.  On receiving the OFFER the remote peer punches its NAT and updates its kernel endpoint, causing a fresh handshake. Outbound OFFERs are rate-limited with exponential backoff starting at 30 seconds and capped at 300 seconds per peer. In addition to proactive polling, <b>active</b> peers also respond to incoming OFFERs when the tunnel is down: the daemon sends its own current endpoint back immediately, so both sides can punch their respective NATs concurrently.  This cuts cold-start latency in active-active configurations from up to one full backoff cycle to a few seconds. Use <b>active</b> for server-to-server tunnels and for any peer that is expected to be persistently online.

- <b>passive</b>
<!-- TROFF sp  -->
  The daemon never initiates outbound PeerJS signalling for this peer. However, when an incoming OFFER arrives from the remote peer and the tunnel is down, the daemon automatically responds with its own current endpoint.  This allows the remote peer to punch its NAT toward this host even when the remote peer is behind a restricted-cone NAT that requires knowing the destination endpoint before it will forward traffic. Use <b>passive</b> for mobile devices or intermittently-connected clients that should initiate contact themselves.  The server-side daemon will respond to each client's OFFER so that both NATs are punched before the WireGuard handshake fires.

- <b>dns-roam</b>
<!-- TROFF sp  -->
  PeerJS is not used.  Instead, the daemon resolves the hostname given in <b>DnsHost</b> every poll cycle.  When the resolved address changes it calls <b>wg set *iface* peer *pubkey* endpoint *ip*:*port*</b> and wakes the kernel WireGuard module to trigger a new handshake. Use <b>dns-roam</b> for peers behind dynamic DNS (DDNS) where you control the hostname but the underlying IP changes unpredictably.

- <b>ignore</b>
  The daemon takes no action for this peer.  Useful for upstream VPN provider tunnels, relay servers, or any peer whose endpoint is managed by another mechanism.

### OFFER LOOP PROTECTION

When two responsive peers exchange OFFERs continuously without the tunnel ever coming up (for example because of a symmetric NAT on one side, or a routing black-hole), the daemon applies the following safeguards:
- 
  A rate-limit prevents sending more than one outbound OFFER per 25 seconds per peer, regardless of how many incoming OFFERs arrive.
- 
  A rolling-window counter tracks how many OFFER exchanges occur within a 10-minute window.  When the counter reaches 8 without the tunnel recovering, the daemon logs a <b>WARNING</b> and enters a 5-minute <i>quarantine</i> for that peer: all responsive OFFERs are suppressed until the quarantine expires.  This bounds worst-case broker traffic to roughly one OFFER per 25 seconds during active exchange, falling back to at most one burst per 15 minutes under a sustained fault.
- 
  If an OFFER arrives bearing this daemon's own routing ID (which would happen if a host accidentally configures its own public key in its peers.d file), it is discarded with a <b>WARNING</b> and never processed.

After a quarantine period the counter resets and the daemon tries again.  When the tunnel eventually comes up the counter and quarantine state are cleared immediately.

## HOLE-PUNCHING MECHANISM

The hole-punching sequence, as executed after receiving a valid OFFER, is:
- **1.**
  <b>Raw-socket injection.</b> A raw <b>AF_INET/SOCK_RAW</b> socket with <b>IP_HDRINCL</b> sends three empty UDP datagrams to the remote endpoint.  The source port in the hand-crafted IP+UDP header is set to the local WireGuard listen port.  This causes the NAT device to create an outbound mapping from <<i>local_listen_port</i>> to <<i>remote_ip</i>><i>:</i><<i>remote_port</i>> in the NAT table.  The three-packet burst (with a 50 ms gap) hedges against UDP packet loss during NAT state creation.
- 
  Because the kernel WireGuard module binds the listen port exclusively, even <b>SO_REUSEADDR</b>/<b>SO_REUSEPORT</b> is rejected for that port; the raw socket bypasses this restriction because it operates at the IP layer, not the UDP layer.
- **2.**
  <b>Kernel endpoint update.</b> <b>wg set *iface* peer *pubkey* endpoint *ip*:*port*</b> is called to tell the kernel WireGuard module where the remote peer now lives.
- **3.**
<!-- TROFF sp  -->
<!-- TROFF sp  -->
  <b>Handshake wake.</b> A 1-byte UDP datagram is sent through the WireGuard interface using <b>SO_BINDTODEVICE</b> to force it through the correct interface regardless of routing table preference.  The kernel WireGuard module observes the outbound traffic, sees a pending handshake for the updated endpoint, and initiates it. For peers with a <b>/32</b> allowed-ip the datagram is addressed to that host address.  For peers with a wider subnet the first usable host address is used.  For <b>0.0.0.0/0</b> catch-all peers, <b>192.0.2.1</b> (TEST-NET-1, RFC 5737) is used; any address in the /0 range would work, but 192.0.2.1 is unlikely to exist as a real host and is clearly bogon. The conntrack NAT mapping created by the raw injection lasts approximately 30 seconds (default <b>nf_conntrack_udp_timeout</b> on Linux).  The wake step must trigger a handshake within this window; in practice the WireGuard handshake completes in under 1 second.

## CRYPTOGRAPHY

All signalling payloads are end-to-end encrypted; the PeerJS broker sees only opaque blobs and cannot read or modify the endpoint information.

### Key derivation

For each peer pair (A, B) a shared symmetric key is derived:
- **1.**
<!-- TROFF sp  -->
  Perform X25519 Diffie-Hellman: <b>shared = X25519(my_wg_private_key, peer_wg_public_key)</b>
- **2.**
<!-- TROFF sp  -->
  Apply keyed BLAKE2b for domain separation: <b>key = BLAKE2b-256(shared, key=wg-peerjs/v1/sigbox)</b>

The domain label ensures that this key is cryptographically independent from WireGuard's own session keys, even though both derive from the same Curve25519 keypair.

### Payload encryption

  Payloads are encrypted with <b>libsodium SecretBox</b> (XSalsa20-Poly1305).  Each payload contains:

  - <b>v</b>
    Protocol version (integer, currently 1).  Recipients reject mismatches.

  - <b>ts</b>
    Unix timestamp of encryption time (integer seconds).  Recipients reject messages older than 90 seconds or more than 90 seconds in the future, providing replay protection.

  - <b>ip</b>
    The sender's current public IPv4 address (string).

  - <b>port</b>
  The sender's WireGuard listen port (integer).

  The encrypted blob is base64-encoded and carried in <b>payload.metadata.blob</b> of the PeerJS OFFER envelope.

### Endpoint validation

On receipt, the decrypted endpoint is sanity-checked before being applied to the kernel: loopback, link-local, multicast, unspecified, and reserved addresses are rejected.  Port numbers outside 1–65535 are rejected.  This prevents a compromised peer or broker from redirecting WireGuard handshakes to infrastructure services.

## PEERJS ROUTING IDENTITY

Each daemon instance registers on the signalling broker under a deterministic routing ID derived from its WireGuard public key and the shared salt:

<b>routing_id = SHA-256(wg_public_key_bytes || salt_bytes).hexdigest()</b>

Because the salt is site-specific and not embedded in the public key, two installations running the same WireGuard key with different salts will not interfere with each other on the public broker.

The daemon opens <i>one</i> long-lived WebSocket connection per process, not one per peer.  This is deliberate: a single connection is sufficient for all configured peers (routing IDs are per-peer, not per-connection), and avoids multiplying broker load with the number of peers.

The routing ID is keyed to the WireGuard interface whose public key the daemon chose as the "primary" interface (the one hosting the most non-IGNORE configured peers).  Peers configured on <i>other</i> WireGuard interfaces on the same host will not reach this daemon over PeerJS until multi-interface support is added.  A warning is logged when this situation is detected.

## PEERJS WIRE FORMAT

All signalling messages use the standard PeerJS OFFER wire format: a WebRTC datachannel OFFER envelope with freshly generated ICE credentials and a DTLS fingerprint in the SDP body.  The encrypted endpoint blob is carried in <b>payload.metadata.blob</b> alongside the standard WebRTC fields.

This format is used unconditionally — with both self-hosted and public brokers — so there is one wire format regardless of deployment.

### Discriminator: **payload.metadata.kind**

The <b>kind</b> field inside <b>payload.metadata</b> discriminates between three message families that all share the OFFER envelope:

- <b>(absent or "offer")</b>
  Ordinary signalling OFFER.  The encrypted blob carries a <b>candidates</b> list (see below); the receiver applies the first valid candidate to the kernel WG endpoint and (when the tunnel is DOWN) sends a responsive OFFER carrying its own endpoint(s).

- <b>signal_wake</b>
  Client-initiated wake.  The encrypted blob carries an <i>empty</i> <b>candidates</b> list — the sender hasn't claimed an endpoint, it's asking the receiver to refresh its view.  The receiver does NOT touch kernel WG state from a wake (no endpoint claim to apply).  It DOES send a responsive OFFER carrying its own endpoint(s), <i>bypassing the "tunnel-already-UP" guard</i> that suppresses ordinary responsive OFFERs, since wakes are explicit user-driven requests.  The same OFFER-loop rate-limiters apply.

- <b>enroll" / "enroll_ok" / "enroll_err</b>
  Auto-enrollment.  See AUTO-ENROLLMENT below.

### Encrypted blob: **candidates** list

The decrypted <b>blob</b> plaintext is JSON of the form:

```
{
  "v": 1, "ts": <epoch_seconds>,
  "candidates": [
    {"ip": "192.168.43.1", "port": 51820, "kind": "lan"},
    {"ip": "1.2.3.4",      "port": 51820, "kind": "stun"}
  ]
}
```

<b>Senders</b> list candidate endpoints in preference order: a phone in host-mode-on- hotspot fills <b>[LAN, STUN]</b> so on-LAN guests pick the LAN candidate without crossing the public IP (avoiding cellular hairpin-NAT failure).  An ordinary single-endpoint daemon fills exactly one entry.  Senders that don't claim any endpoint (today, <b>signal_wake</b>) fill an empty list.

<b>Receivers</b> take the first candidate that passes <b>is_valid_public_endpoint</b> (rejects loopback, link-local, multicast, unspecified, reserved, and weirdly-low ports — RFC 1918 private addresses are accepted on the assumption the sender saw a LAN candidate and the receiver is on the same LAN).  Kernel WireGuard endpoint roaming sorts out the rest from real handshake traffic — no need for the receiver to time-share between candidates.

<b>Per-candidate</b> <b>kind</b> is purely informational (<b>lan</b>/<b>stun</b>/<b>dns</b>/<b>manual</b>; future expansion: **v6ll**, **pcp**).  Receivers do not interpret the field; it shows up only in diagnostic logs.

## AUTO-ENROLLMENT

Auto-enrollment lets a freshly-installed client join an existing <b>wireguardrtc</b> mesh by scanning a one-time QR code, with no manual exchange of public keys.  The protocol is opt-in: enable <b>[Enrollment] Enabled = yes</b> in the global config and configure <b>ProvisionScript</b>.

### Threat model

The voucher (token in the QR code) is the trust anchor.  Anyone in possession of a token can enroll a single device until the token is consumed or expires.  The protocol guarantees:
- 
  <b>Confidentiality.</b> The PeerJS broker sees only routing IDs and ciphertext.  Endpoint addresses, name hints, and device strings are encrypted with a key derived from the token plus an X25519 ECDH between the client's and server's WireGuard keypairs.
- 
  <b>Server authentication.</b> The encrypted ENROLL_OK / ENROLL_ERR response carries an authentication tag that only the server (holder of its private WireGuard key) can produce.  A passive observer cannot forge a response, and a forged response from any other party fails the client's auth-tag check.
- 
  <b>Single-use enforcement.</b> The server marks tokens as consumed atomically before invoking the provisioning hook.  Concurrent racers serialize on a file lock; the loser receives an authenticated <b>TOKEN_USED</b> response so the legitimate user <i>notices the failure</i> rather than silently re-enrolling onto a stolen identity.
- 
  <b>Replay safety.</b> A successful enrollment response is cached server-side for 5 minutes, keyed by the client's public key.  Legitimate retries (lost <b>ENROLL_OK</b> over a flaky network) return the same envelope; only the holder of the matching private key can decrypt it.

<b>What auto-enrollment does NOT protect against:</b> QR-code leakage.  If an attacker observes the QR before the legitimate user does, they can race for the token.  In a small-scale deployment this is acceptable: the loser sees an authenticated <b>TOKEN_USED</b> error and surfaces a prominent failure to the user, who can then ask the admin to revoke the rogue enrollment and mint a fresh token. Treat QR images like one-time passwords — share over E2EE channels or in person, not via plaintext email.

### Wire format

Both <b>ENROLL</b> and the corresponding <b>ENROLL_OK</b> / <b>ENROLL_ERR</b> responses ride inside the same WebRTC OFFER envelope used by signalling traffic; they are discriminated by a <b>kind</b> field inside <i>payload.metadata</i>:
- 

```
"metadata": {
    "v":          1,
    "kind":       "enroll" | "enroll_ok" | "enroll_err",
    "client_pub": "<X25519 base64>",   // ENROLL only
    "server_pub": "<X25519 base64>",   // ENROLL_OK / ENROLL_ERR only
    "blob":       "<base64 secretbox>"
}
```

- 
  The <b>blob</b> is encrypted under a key derived as:
- 

```
shared     = X25519(local_priv, peer_pub)
enroll_key = BLAKE2b-32(shared,    key="wg-peerjs/v1/enroll")
final_key  = BLAKE2b-32(enroll_key, key=token)
ciphertext = secretbox(plaintext, key=final_key)
```

- 
  Domain separation guarantees: the enrollment key cannot collide with the signalling key (which uses <i>wg-peerjs/v1/sigbox</i>) and re-keying with <b>token</b> binds each ciphertext to a specific single-use voucher.

### URI format

The minted token is encoded as a <b>wgrtc-enroll://v1?...</b> URI suitable for embedding in a QR code:
- 

```
wgrtc-enroll://v1?
    pk=<server_pubkey, b64url no padding>
    &salt=<salt, b64url no padding>
    &broker=<wss-url>
    &brokerkey=<peerjs key>
    &token=<32-byte token, b64url no padding>
    &expires=<unix seconds>
    &server=<NAME>
```

### Operations

<b>Mint a token (admin):</b>
- 

```
sudo wireguardrtc --enroll-token "Anna's Pixel 8"
```

- 
  Prints the URI on stdout and a terminal QR code (when stdout is a TTY and <b>qrencode</b>(1) is installed).  The daemon must be running for the token to be processed; the <b>--enroll-token</b> mode itself just persists the token to <i>StateDir/pending-tokens.json</i> and exits.

<b>Honour an enrollment request (server, automatic):</b> The running daemon listens for <b>ENROLL</b> messages on its PeerJS connection.  On receipt:
- **1.**
  Try-decrypt the ciphertext against each unexpired token in <i>pending-tokens.json</i>.
- **2.**
  Validate the inner timestamp is within ±90 s of current time.
- **3.**
  Atomically claim the token (compare-and-swap under <b>flock</b>(2)).
- **4.**
  Invoke <b>ProvisionScript</b> with the new peer's <i>IFACE</i>, <i>NAME</i>, and base64-encoded public key.
- **5.**
  Read back the allocated address via <b>wg show *IFACE* allowed-ips</b>.
- **6.**
  Build, encrypt, and send the <b>ENROLL_OK</b> response.  Cache it for 5 minutes for retry safety.

On any failure that the client should <b>notice</b> (token already consumed, provisioning script error), the daemon sends an authenticated <b>ENROLL_ERR</b> response carrying a machine-readable <b>code</b> field.  On any failure that should <b>not</b> leak token state (no decryption succeeded — could be wrong key, no such token, or expired token), the daemon silently drops the request and logs at <b>WARNING</b> level on its own side.

## LIVE KERNEL STATE

  The daemon never parses WireGuard <i>.conf</i> files.  All peer and interface state is read from the running kernel via <b>wg show</b> subcommands:

  - <b>wg show interfaces</b>
    Enumerate WireGuard interfaces.

  - <b>wg show *iface* private-key</b>
    Read private key (requires <b>CAP_NET_ADMIN</b>).

  - <b>wg show *iface* public-key</b>
    Read public key.

  - <b>wg show *iface* listen-port</b>
    Read the bound UDP port.

  - <b>wg show *iface* latest-handshakes</b>
    Get the last handshake time (Unix seconds) for each peer.

  - <b>wg show *iface* endpoints</b>
    Get the current kernel endpoint for each peer.

  - <b>wg show *iface* allowed-ips</b>
  Read the allowed-ip prefixes, used to select a wake target.

  The state is refreshed every <b>POLL_INTERVAL</b> seconds (30 s).

## SIGNALS

- <b>SIGTERM</b>, <b>SIGINT</b>
  Initiates a clean shutdown: the PeerJS WebSocket is closed, all asyncio tasks are cancelled, and the process exits with status 0.

There is no <b>SIGHUP</b> reload; restart the daemon with <b>systemctl restart wireguardrtc</b> to pick up configuration changes.

## EXIT STATUS

- <b>0</b>
  Clean shutdown (SIGTERM or SIGINT received).

- <b>2</b>
  Fatal configuration or capability error: missing or placeholder Salt; missing global configuration file; no usable WireGuard interface found; cannot create raw socket (missing <b>CAP_NET_RAW</b>); cannot read WireGuard private key (missing <b>CAP_NET_ADMIN</b>); another instance already holds the lock file; or a required Python package is not installed.

Exit status 2 is treated as a permanent failure by the systemd unit (<b>RestartPreventExitStatus=2</b>); the service will not be restarted automatically until the administrator corrects the configuration and runs <b>systemctl start wireguardrtc</b>.

## ENVIRONMENT

- <b>WIREGUARDRTC_CONFIG_DIR</b>
  Overrides the base directory for both the global config file and the peers directory.  Default: <i>/etc/wireguardrtc</i>. Useful for testing without touching system files.

- <b>LOG_LEVEL</b>
  Default log level, equivalent to <b>--log-level</b>. Respected only when <b>--log-level</b> is not given on the command line.

- <b>PYTHONUNBUFFERED</b>
  Set to <b>1</b> by the systemd unit so that log lines are written to the journal immediately rather than being held in Python's stdio buffer.

## FILES

- <i>/etc/wireguardrtc/wireguardrtc.conf</i>
  Global daemon configuration.  Owned <b>root</b>:<b>wireguardrtc</b>, mode <b>0640</b>. See <b>CONFIGURATION FILES</b> above.

- <i>/etc/wireguardrtc/peers.d/*.conf</i>
  Per-peer drop-in files.  Same ownership and mode as the global config.  See <b>CONFIGURATION FILES</b> and <b>PEER MODES</b> above.

- <i>/var/lib/wireguardrtc/auto-enrolled.d/*.conf</i>
  Auto-generated per-peer drop-ins, one per successfully-enrolled peer.  Format identical to <i>/etc/wireguardrtc/peers.d/*.conf</i>; default <b>Mode = active</b> so the daemon pushes signalling OFFERs to the new peer (Phase-2 endpoint roaming on the Android client relies on this).  Disabled by setting <b>[Enrollment] AutoActive = no</b> in <i>wireguardrtc.conf</i>. Admin entries in <i>/etc/wireguardrtc/peers.d/</i> override entries here on <b>PublicKey</b> collision.

- <i>/run/wireguardrtc/lock</i>
  Single-instance lock file.  The daemon acquires an exclusive <b>flock</b>(2) on this file at startup; subsequent instances exit immediately with an error.  The directory <i>/run/wireguardrtc</i> is created by the systemd <b>RuntimeDirectory=wireguardrtc</b> directive and removed when the service stops.

- <i>/usr/sbin/wireguardrtc</i>
  The daemon executable.

- <i>/usr/sbin/wireguardrtc-key-oracle</i>
  The privileged key-derivation oracle.  Holds WireGuard private keys and serves derive_sigbox/derive_enroll/set_endpoint requests over <i>/run/wireguardrtc/oracle.sock</i>. Sole holder of <b>CAP_NET_ADMIN</b> on the host.

- <i>/usr/sbin/wireguardrtc-raw-helper</i>
  The privileged raw-socket helper.  Sends the hole-punch inject and the WG-iface-bound wake-up datagram on validated inputs from the daemon, over <i>/run/wireguardrtc/raw.sock</i>. Sole holder of <b>CAP_NET_RAW</b> on the host.

- <i>/usr/sbin/wireguardrtc-provision-client</i>
  Daemon-side hook for the provisioning broker.  Default <b>ProvisionScript</b> in <i>wireguardrtc.conf</i>; runs in the daemon's sandbox and forwards the request to the broker over a Unix socket.

- <i>/usr/sbin/wireguardrtc-provision-broker</i>
  Privileged side of the provisioning channel.  Reads one request from stdin, validates strictly, invokes the configured Provisioner, writes the result to stdout.  Not invoked directly by admins — started via socket activation by <i>wireguardrtc-provision-broker@.service</i>.

- <i>/usr/sbin/wireguardrtc-provision-default</i>
  Default Provisioner for stock <b>wg-quick</b>(8) deployments.  Allocates from a CIDR pool and writes <b>[Peer]</b> blocks to <i>/etc/wireguard/IFACE.conf</i>. Override in <i>/etc/wireguardrtc/provision-broker.conf</i>.

- <i>/etc/wireguardrtc/provision-broker.conf</i>
  Names the upstream Provisioner the broker invokes.  See the example under <i>/usr/share/doc/wireguardrtc/examples/</i>.

- <i>/etc/wireguardrtc/provisioning.conf</i>
  Read by <b>wireguardrtc-provision-default</b> only.  Defines the CIDR pool for auto-allocated peer addresses.

- <i>/run/wireguardrtc-provision/sock</i>
  Unix socket the daemon-side client writes provision requests to. Created by <i>wireguardrtc-provision-broker.socket</i> on first request.

- <i>/var/lib/wireguardrtc-provision-broker/permits/<urlsafe_token></i>
  Single-use permit dropped by <b>wireguardrtc --enroll-token</b> when an admin mints a token; consumed by the broker on first provisioning request that matches.  Mode <b>0700</b>, root-owned; the daemon process cannot write here, which is what gates provisioning to the actual mint→consumption window.

- <i>/lib/systemd/system/wireguardrtc.service</i>
  systemd unit file for the daemon.

- <i>/lib/systemd/system/wireguardrtc-provision-broker.socket</i>

- <i>/lib/systemd/system/wireguardrtc-provision-broker@.service</i>
  systemd socket and per-connection service template for the broker. Enable with <b>systemctl enable --now wireguardrtc-provision-broker.socket</b> when auto-enrollment is in use.

- <i>/usr/share/man/man8/wireguardrtc.8.gz</i>
  This manual page.

- <i>/usr/share/doc/wireguardrtc/examples/peers.d/</i>
  Example per-peer drop-in files (active-peer.conf, passive-mobile.conf, dns-roam.conf).  Copy and edit as needed.

## SECURITY

### Privilege model

The package ships three services with carefully partitioned capabilities.  The daemon process holds <b>no</b> capabilities at all; both <b>CAP_NET_ADMIN</b> and <b>CAP_NET_RAW</b> live in tiny sibling helpers that the daemon talks to over Unix sockets.

- <b>wireguardrtc.service</b>
  The main daemon — receives PeerJS messages, decrypts OFFERs, dispatches enrollment, runs the polling loop.  Runs as the <b>wireguardrtc</b> user with <b>no Linux capabilities .</b> After RCE on the daemon a kernel-level privileged syscall is rejected outright; the daemon can only issue narrow RPCs to its helpers, each of which validates inputs.

- <b>wireguardrtc-key-oracle.service</b>
    Holds the WireGuard private keys.  Runs as the <b>wireguardrtc</b> user with <b>CAP_NET_ADMIN</b> only.  Serves three RPCs over <i>/run/wireguardrtc/oracle.sock</i>:
    - 
      <b>derive_sigbox</b> (*iface, peer_pub*) -> 32-byte signalling key
    - 
      <b>derive_enroll</b> (*iface, peer_pub, token*) -> 32-byte enrollment key
    - 
    <b>set_endpoint</b> (*iface, peer_pub, ip, port*) -> bool — refuses to silently create new peers (peer must already be in <i>allowed-ips</i>), refuses loopback / link-local / multicast / reserved IPs, refuses ports outside 1..65535
    - 
      The raw 32-byte private key never leaves this process, so an RCE on the daemon cannot lift it for use against the host's WireGuard mesh identity.

    - <b>wireguardrtc-raw-helper.service</b>
        Holds <b>CAP_NET_RAW</b> for the spoofy operations the protocol needs.  Runs as the <b>wireguardrtc</b> user.  Serves two RPCs over <i>/run/wireguardrtc/raw.sock</i>:
        - 
          <b>inject</b> (*iface, src_port, dst_ip, dst_port*) -> bool — sends the 3-packet hole-punch burst with spoofed source port. Refuses if <i>src_port</i> doesn't match the iface's actual listen-port from <b>wg show</b>, or if <i>dst_ip</i> fails the same loopback/link-local/multicast/reserved check the daemon used to apply.
        - 
        <b>wake</b> (*iface, target_ip*) -> bool — sends one zero-byte UDP via <b>SO_BINDTODEVICE</b> on the WG iface so kernel WG triggers a handshake.  Permits RFC 5737 documentation IPs because <i>target_ip</i> is consumed by kernel WG (which encrypts before egress) and has no exfiltration potential.
        - 
          After RCE on the daemon an attacker can ask this helper to inject spoofed packets, but only to publicly-routable IPs and only with the host's own WireGuard listen-port as source.

        - <b>wireguardrtc-key-oracle.service</b>
            The privileged key-derivation oracle.  Reads private keys from the kernel via <b>wg show *iface* private-key</b>, holds them in memory, and serves a small JSON-RPC interface (<b>derive_sigbox</b>, <b>derive_enroll</b>, <b>set_endpoint</b>) over a Unix socket at <i>/run/wireguardrtc/oracle.sock</i> to the daemon.  Runs as the same <b>wireguardrtc</b> user with:
            - 
            <b>CAP_NET_ADMIN</b> — sole purpose: read private keys and call <b>wg set</b>.
            - 
              The oracle never opens an internet socket, never reads <i>/etc</i>, and is heavily seccomp-filtered (same <b>@system-service</b> profile as the daemon, but without <b>@debug</b>). The daemon process therefore cannot <b>ptrace</b>(2) the oracle to lift keys out of its address space, even though both processes run as the same user.

            The recommended deployment uses the static system user <b>wireguardrtc</b> (created by the Debian package's <b>postinst</b> script) and grants only the two required capabilities via <b>AmbientCapabilities</b>. The configuration directory <i>/etc/wireguardrtc</i> is owned <b>root</b>:<b>wireguardrtc</b> with mode <b>0750</b> so that the daemon user can read it but unprivileged users cannot access the salt (which is sensitive: it determines the routing identity on the shared signalling broker).

### Signalling security

The PeerJS broker is treated as an untrusted relay. All endpoint information is encrypted with <b>SecretBox</b> before transmission; the broker cannot learn the IP address or port of any peer, and cannot forge or replay endpoint updates (the freshness window is 90 seconds).

Two different installations that share the same WireGuard key pair but use different salts are cryptographically isolated on the broker: their routing IDs will not collide, and their payloads are encrypted under different derived keys.

### Endpoint acceptance

Received endpoints are validated to reject loopback, link-local, multicast, unspecified, and reserved addresses before being applied to the kernel.  This limits the impact of a key compromise: a compromised peer cannot redirect WireGuard handshakes to infrastructure services such as cloud metadata endpoints.

### Auto-enrollment privilege separation

The daemon is the only component directly exposed to internet traffic (via the PeerJS WebSocket and the kernel WireGuard endpoint), so its RCE blast radius is the dominant attack-surface concern.  Auto-enroll provisioning would otherwise let a compromised daemon write arbitrary <b>[Peer]</b> blocks into <i>/etc/wireguard/</i>, persisting backdoor peers across daemon restarts.  The package mitigates this with a privilege-separated broker <b>and</b> a per-mint permit so the broker only accepts requests when an auto-enrollment is actively in progress:
- 
  The daemon's <b>ProvisionScript</b> points at <i>/usr/sbin/wireguardrtc-provision-client</i>, a small wrapper that runs inside the daemon's sandbox and never touches <i>/etc/wireguard</i>.
- 
  The client connects to <i>/run/wireguardrtc-provision/sock</i>, a Unix socket created by <b>wireguardrtc-provision-broker.socket</b> (mode 0660, group <b>wireguardrtc</b>).
- 
  <b>wireguardrtc-provision-broker@.service</b> is socket-activated, runs as root with <b>CAP_NET_ADMIN</b> only (other root capabilities dropped via <b>CapabilityBoundingSet</b>), and is reinstantiated per request.  It strictly validates the <i>(iface,</i>name,<i>pubkey,</i>token) tuple it receives — <i>iface</i> must match <i>^wg[0-9]+(p[0-9]+)?$</i>, <i>name</i> must match <i>[w</i>.'-]{1,64} (Unicode letters/digits/underscore plus space, dot, apostrophe, hyphen — deliberately permissive enough for "Anna's Pixel 8" and similar real-world names), <i>pubkey</i> must be 44-char standard base64 decoding to exactly 32 bytes, <i>token</i> must be 43-char URL-safe base64 decoding to exactly 32 bytes — then invokes the configured Provisioner (default <i>/usr/sbin/wireguardrtc-provision-default</i>; override in <i>/etc/wireguardrtc/provision-broker.conf</i>).
- 
  <b>Permit gating.</b> For every minted token, <b>wireguardrtc --enroll-token</b> also drops a single-use permit file in <i>/var/lib/wireguardrtc-provision-broker/permits/<urlsafe_token></i>, in a directory the daemon process cannot write to (mode <b>0700</b>, root-owned).  The broker requires a matching permit to be present before invoking the Provisioner; the permit is unlinked before provisioning runs (single-use enforced even if the Provisioner fails).  Effect: outside the window between mint and consumption, broker requests are flatly refused — a daemon RCE cannot synthesize a permit because it has no write access to the directory, and cannot provision peers at all without a corresponding admin-issued mint.
- 
  After RCE on the daemon an attacker can attempt to hijack an in-flight enrollment by racing the legitimate broker call with their own pubkey under the same name, but they cannot provision out of band, cannot read existing configuration, cannot modify peers other than via the validated path, and cannot gain shell access.  The legitimate client whose token was hijacked receives an authenticated <b>TOKEN_USED</b> response, so the failure is user-noticeable per <b>Threat model</b> above.  The broker's request shape is the entire RPC surface.

This is the same privsep pattern OpenSSH uses to keep the network-facing <b>sshd</b> process from holding the host private key directly.  The companion <b>wireguardrtc-key-oracle.service</b> applies the same pattern to the WireGuard private keys themselves (see <b>Privilege model</b> above).

### Limitations

- 
  <b>Symmetric NAT is not supported.</b> Only cone-NAT topologies (full-cone, address-restricted, port-restricted) are traversable.  Symmetric NAT requires port prediction, which the daemon does not implement.
- 
  <b>IPv6 hole-punching is not implemented.</b> The raw injection path constructs an IPv4 header only.  Endpoint discovery and publication over IPv6 is on the project roadmap but not yet implemented.
- 
  <b>Single interface limitation.</b> The daemon currently registers a single PeerJS routing ID keyed to one WireGuard interface.  Peers configured on other WireGuard interfaces on the same host will not be reachable via PeerJS until multi-interface support is added.

## TIMING CONSTANTS

The following timing constants are compiled into the daemon.  They are not configurable without editing the source.

```
l l lx.
Constant	Value	Purpose
_
POLL_INTERVAL	30 s	T{
Interval between poll cycles
T}
HANDSHAKE_DEAD_THRESHOLD	180 s	T{
Tunnel considered dead after this
T}
SIGNALING_BACKOFF	300 s	T{
Minimum time between OFFERs per peer
T}
PEERJS_HEARTBEAT	5 s	T{
WebSocket HEARTBEAT cadence
T}
STUN_TIMEOUT	2.5 s	T{
Per-server STUN query timeout
T}
RAW_INJECT_REPEATS	3	T{
Raw-inject burst count
T}
RAW_INJECT_GAP	50 ms	T{
Delay between burst packets
T}
PROTOCOL_FRESHNESS_WINDOW	90 s	T{
Replay protection window ()
T}
```

## DIAGNOSTICS

The daemon logs to standard output / the journal.  Anti-spam filtering is applied via the internal <b>StateLogger:</b> each <i>(scope, key, value)</i> triple is logged only once per value transition.  This means a persistently-dead tunnel generates one log line when it enters the dead state, not one line every 30 seconds.

Useful diagnostic commands:

```
# Follow the live log under systemd
journalctl -fu wireguardrtc

# Verify WireGuard handshakes are occurring
wg show wg0 latest-handshakes

# Confirm raw-injected packets reach the wire
tcpdump -i any udp port 51820

# Check capability grant
systemctl show wireguardrtc -p AmbientCapabilities

# Check effective config directory
systemctl show wireguardrtc -p Environment
```

Common warnings and their meaning:

- <b>OFFER from *label*: decryption/freshness failed</b>
  The OFFER arrived but could not be decrypted or its timestamp was outside the freshness window.  Possible causes: clock skew >90 s between peers, mismatched WireGuard keys, or a replayed OFFER.

- <b>rejected suspicious peer endpoint *ip*:*port*</b>
  The decrypted payload contained a loopback, link-local, multicast, or otherwise disallowed address.

- <b>cannot create raw socket — daemon needs CAP_NET_RAW</b>
  The daemon is running without <b>CAP_NET_RAW</b>. Enable it with <b>AmbientCapabilities=CAP_NET_RAW</b> in the systemd unit, or run as root.

- <b>non-IGNORE peers configured on multiple interfaces</b>
  Peers on more than one WireGuard interface are configured.  Only the primary interface's peers can be reached via PeerJS.  See <b>BUGS</b>.

- <b>*label*: PublicKey *XXX* not present on any WireGuard interface</b>
  A drop-in file references a public key that is not present in the live kernel state.  Check for typos or ensure the WireGuard interface is up.

## EXAMPLES

### Basic setup (two hosts)

On <b>both</b> hosts, generate a shared salt (use the exact same value everywhere):

```
head -c 32 /dev/urandom | base64
```

Add it to <i>/etc/wireguardrtc/wireguardrtc.conf</i> on both hosts:

```
[Global]
Salt = <paste-your-shared-salt-here>
```

On the host that should actively maintain the tunnel, create <i>/etc/wireguardrtc/peers.d/laptop-anna.conf</i>:

```
[Peer]
PublicKey = <base64-public-key-of-anna>
Mode = active
```

On Anna's laptop (passive end), create <i>/etc/wireguardrtc/peers.d/office-server.conf</i>:

```
[Peer]
PublicKey = <base64-public-key-of-server>
Mode = passive
```

Restart the daemon on both hosts after editing any configuration file:

```
systemctl restart wireguardrtc
```

### DNS roaming

For a home server behind a DDNS hostname, no broker involvement is needed.  Create <i>/etc/wireguardrtc/peers.d/home-server.conf</i>:

```
[Peer]
PublicKey = <base64-public-key-of-home-server>
Mode = dns-roam
DnsHost = home.example.com:51820
```

The daemon will resolve <i>home.example.com</i> every 30 seconds and update the WireGuard endpoint when the IP changes.

### Private broker

For deployments that want to avoid the public broker:

```
# On a host with Docker:
docker run -d --name peerjs --restart=always -p 9000:9000 \
    peerjs/peerjs-server --port 9000 --key mysecretkey
```

Then in <i>/etc/wireguardrtc/wireguardrtc.conf</i>:

```
[Global]
PeerJsServer = ws://broker.example.com:9000/peerjs
PeerJsKey = mysecretkey
```

### Testing without system paths

```
export WIREGUARDRTC_CONFIG_DIR=$HOME/wg-test
sudo wireguardrtc --log-level DEBUG
```

## SEE ALSO

<b>wg</b>(8), <b>wg-quick</b>(8), <b>systemd.unit</b>(5), <b>systemd.exec</b>(5), <b>capabilities</b>(7), <b>raw</b>(7), <b>ip</b>(7)

Project design documentation: <i>/usr/share/doc/wireguardrtc/wg-holepunch-guide.md</i>

PeerJS project: <i>https://peerjs.com/</i>

RFC 5389 — Session Traversal Utilities for NAT (STUN).
RFC 5737 — IPv4 Address Blocks Reserved for Documentation.

## BUGS

- 
  Only one WireGuard interface is served by a single daemon process. Peers on secondary interfaces will not receive PeerJS-based hole-punching.
- 
  IPv6 NAT traversal is not implemented.
- 
  There is no SIGHUP reload; the daemon must be restarted to pick up changes to configuration files.
- 
  STUN results are not cached between poll cycles; each outbound OFFER triggers a fresh STUN query.
- 
  Symmetric-NAT topologies are mathematically unsupported by the hole-punching model used here; no workaround exists within this design.

## AUTHORS

Markus Gutschke.
