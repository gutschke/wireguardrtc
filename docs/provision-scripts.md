# Writing a custom ProvisionScript

When a peer enrolls — either via the original token-based flow
(`--enroll-token` minted by an admin) or the wormhole-pairing flow
(`--mint-wormhole`, where the joiner types a 6-letter code and both
sides verify a SAS phrase) — the daemon calls a user-supplied
**ProvisionScript** to add the new peer to the running WireGuard
interface.  This script is the integration point with whatever
peer-management system the operator already uses (`wg-quick` config
files, an Ansible inventory, a `*.peers` index file shared by an
add-peer / del-peer family of helpers, an IPAM, etc.).

This guide is the recipe for writing one.

## Contract

```
ProvisionScript IFACE NAME PUBKEY_BASE64
```

The daemon invokes the script with three positional arguments:

| Arg | Meaning | Validation already done by the daemon |
|---|---|---|
| `IFACE` | The WireGuard interface the peer joins (`wg0`, `wgvpn`, …). | Matches `^[A-Za-z0-9._-]{1,15}$` and is one of the interfaces the daemon is currently watching. |
| `NAME` | A short human-readable label the admin (or the joiner) supplied. | Matches `^[A-Za-z0-9._@-]{1,64}$` — no shell metacharacters, no spaces, no `/`. |
| `PUBKEY_BASE64` | The joiner's WireGuard public key. | Decodes to exactly 32 bytes via standard base64. |

The script also receives one environment variable for the token-based
enrollment path:

| Env | Meaning |
|---|---|
| `WIREGUARDRTC_PROVISION_TOKEN` | URL-safe-base64 (no padding) of the 32-byte enrollment token the daemon just claimed.  Present for `--enroll-token` flows, absent for `--mint-wormhole` flows (the wormhole code is one-shot in a different way). |
| `WIREGUARDRTC_PROVISION_PARAMETERS` | Site-specific parameter string the admin attached when minting.  Present when the wormhole-pair admin used `--parameters STR` (or, in token-based flows, when a script-managed wrapper stashed parameters elsewhere — convention is up to the operator).  Absent when no parameters were supplied.  Format is a string the script defines; a common convention is `key=value, key=value, …`. |

The script must:

- Exit with status **0** on success — the daemon then reads the peer's
  assigned address back via `wg show <IFACE> allowed-ips`.
- Exit non-zero on any failure.  Stderr is captured into the daemon's
  log; stdout is ignored.
- Complete within **15 seconds** (the default hard timeout — see
  `_PROVISION_TIMEOUT_S` in the daemon source).  Long-running work
  (DNS, package installs, …) must happen out-of-band.

## Minimal example: append a `[Peer]` block

The simplest possible ProvisionScript appends a `[Peer]` block to the
relevant `wg-quick` config and tells the running interface about it:

```bash
#!/bin/bash -e
# /etc/wireguard/provision.sh
# Args: IFACE NAME PUBKEY_BASE64

iface="${1:?IFACE missing}"
name="${2:?NAME missing}"
pubkey="${3:?PUBKEY missing}"

# Allocate the next free /32 from the host's CIDR — simplistic
# example; real deployments use IPAM or a structured peers file.
state=/var/lib/wireguardrtc/next-slot
mkdir -p "$(dirname "$state")"
n=$(cat "$state" 2>/dev/null || echo 2)
addr="10.99.0.${n}/32"
echo $((n + 1)) > "$state"

# Add the peer to the live interface AND persist it.
wg set "$iface" peer "$pubkey" allowed-ips "$addr"
cat >> "/etc/wireguard/${iface}.conf" <<EOF

[Peer]
# Provisioned for $name at $(date -u --iso-8601=seconds)
PublicKey = $pubkey
AllowedIPs = $addr
EOF
```

Configure it in `/etc/wireguardrtc/wireguardrtc.conf`:

```ini
[Enrollment]
Enabled         = yes
ProvisionScript = /etc/wireguard/provision.sh
```

## Privilege model

The daemon runs heavily sandboxed (`User=wireguardrtc`,
`ProtectSystem=strict`, `CapabilityBoundingSet` near-empty — see the
shipped systemd unit).  It **cannot** write to `/etc/wireguard/`,
cannot call `wg set`, cannot read most of the filesystem.  This is
deliberate: the daemon talks to an untrusted broker over WSS, parses
attacker-controlled bytes, and runs continuously.  A bug in that code
path must not be able to overwrite the WG config.

So `ProvisionScript` should normally point at one of the daemon's
shipped wrappers, which forward the request over a Unix socket to a
**root-running broker** that then invokes your real script:

```
ProvisionScript = /usr/sbin/wireguardrtc-provision-client
```

The broker (`wireguardrtc-provision-broker(8)`) reads
`/etc/wireguardrtc/provision-broker.conf` for the actual command to
execute on each enrollment.  Set yours there:

```ini
# /etc/wireguardrtc/provision-broker.conf
Helper = /etc/wireguard/provision.sh
```

Pointing `ProvisionScript` directly at a script that writes to
`/etc/wireguard/` only works if you've also relaxed the daemon unit's
sandbox — and **don't** do that lightly.  See the `SECURITY` section
of `wireguardrtc(8)`.

## Idempotency

The daemon's enroll-token logic guarantees a token is one-shot, but
edge cases (broker retransmits, daemon restart mid-flow) can cause
the same `(IFACE, NAME, PUBKEY)` triplet to arrive twice.  Make the
script idempotent: re-running it for an already-known peer must
succeed without duplicating the entry.

A common pattern is "delete-then-add" of the peer line:

```bash
sed -i "/^PublicKey = $pubkey\$/,/^$/d" "/etc/wireguard/${iface}.conf"
# ... then append fresh ...
```

`wg set <iface> peer <pubkey> ...` itself is idempotent — repeated
calls update the existing peer's settings rather than adding a
duplicate.

## Concurrency

Two enrollments can race.  Wrap the script body in `flock`:

```bash
lock=/run/wireguardrtc/provision.lock
exec 9<>"$lock"
flock 9
# ... mutex-protected body ...
```

The shipped `wireguardrtc-provision-broker` already serializes
requests across its Unix-socket clients, so the lock is only
necessary if you call the script outside the broker (e.g. directly,
or from an admin helper like `add-peer`).

## Reading the token (for ENROLL-style flows)

The `WIREGUARDRTC_PROVISION_TOKEN` env var carries the same token bytes
the joiner's QR code / URI contained, base64url-no-pad.  This is
useful when the script needs to look up admin-supplied parameters
that were stashed at mint time:

```bash
token="${WIREGUARDRTC_PROVISION_TOKEN:-}"
# Decode and use as a key into your pending-tokens database.
```

Wormhole-pair flows don't set this env var — the code itself is the
shared secret and is one-shot for a different reason (SAS-verified
PAKE).  Scripts that branch on the env var's presence work cleanly
for both paths:

```bash
if [ -n "${WIREGUARDRTC_PROVISION_TOKEN:-}" ]; then
    # Token-based enroll; look up admin-supplied parameters by token.
    parameters="$(lookup_pending_token "$WIREGUARDRTC_PROVISION_TOKEN")"
else
    # Wormhole-pair; admin parameters were typed on the host CLI
    # via --mint-wormhole flags.  Use defaults.
    parameters=
fi
```

## Worked example: the `add-peer` / `provision-rtc` family

A common deployment style is to keep peers in a single index file
(`/etc/wireguard/<iface>.peers`) and have separate `add-peer`,
`del-peer`, `show-peer` admin tools rewrite the live config from
that index.  In that style, the ProvisionScript looks like:

```bash
#!/bin/bash -e
ifc="$1"; name="$2"; pubkey="$3"
peers="/etc/wireguard/${ifc}.peers"

# Pending-token sidecar carries admin parameters (target=, reverse=, …).
pending="/etc/wireguard/${ifc}.pending-rtc/${name}"
parameters=
[ -r "$pending" ] && parameters="$(grep '^parameters=' "$pending" | cut -d= -f2-)"

# Append under flock so concurrent enrolls can't garble the file.
exec 9<>"/run/wireguardrtc/provision.lock"
flock 9
printf '%s %s %s\n' "$name" "$pubkey" "$parameters" >> "$peers"

# Apply just this one peer to the running interface.
config-peers "$ifc" "$pubkey"

rm -f "$pending"
```

The matching `add-peer-rtc` admin tool calls
`wireguardrtc --enroll-token NAME` to mint a token, then drops a
pending-token sidecar with the parameters the operator specified.
Both halves cooperate to give the operator a single command-line
entry point that handles QR display, parameter staging, and the
hand-off to the daemon.

## Testing your script

Test the script standalone before wiring it to the daemon:

```bash
# Pretend we're the daemon — call the script with sample args.
sudo IFACE=wg0 NAME=test PUBKEY=$(wg genkey | wg pubkey | base64 -w0) \
    /etc/wireguard/provision.sh "$IFACE" "$NAME" "$PUBKEY"

# Verify the peer landed:
wg show wg0 peers
```

Then re-run with the same args and verify it stayed idempotent.

Then make the daemon call it for real with the token-based flow:

```bash
sudo wireguardrtc --enroll-token testpeer --expires 300
# Type the resulting wgrtc-enroll://… URI into the joiner.
```

Or with the wormhole-pair flow:

```bash
sudo wireguardrtc --mint-wormhole --iface wg0
# Type the 6-letter code on the joiner.
```

Watch `journalctl -fu wireguardrtc` while the joiner enrolls — the
ProvisionScript's stderr is forwarded there with the prefix
`provision:`.

## Reference

- Manual page: `wireguardrtc(8)` §`[Enrollment]`.
- Shipped wrapper: `/usr/sbin/wireguardrtc-provision-client`.
- Shipped broker:  `/usr/sbin/wireguardrtc-provision-broker`.
- Shipped default helper:
  `/usr/sbin/wireguardrtc-provision-default` — a working
  ProvisionScript that allocates from a CIDR pool, useful as a
  template.
