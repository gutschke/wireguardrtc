# IPv6 Through wgrtc Tunnel on ChromeOS — Diagnostic Test Plan

**Status:** Open investigation as of 2026-05-16.

## Background

The current working hypothesis (see README "Known limitations") is
that v6 through the wgrtc tunnel works for ARC apps, partially fails
for ChromeOS-host apps via a Patchpanel v6 forwarding gap, and fully
bypasses the tunnel for Crostini.  We're not 100% confident — it's
suspicious that ChromeOS would ship VPN support that's this broken
for v6, especially given the existence of v6-only networks.

This document is a structured test plan to either confirm the
diagnosis or find the true root cause.  Run tests roughly in the
order listed; later phases depend on conclusions from earlier ones.

Run each test, write down the **actual** output below the expected
one, and update the "What this tells us" column with your reading.
We'll iterate until the picture is solid.


## Tools you'll want available

- **ChromeOS-host**: `crosh` (`Ctrl+Alt+T`).
- **ARC**: `adb -s localhost:5555 shell` (via ssh forwarding).
- **Crostini**: `crosh; vsh termina; lxc exec penguin bash`.
- **Server**: `ssh root@wireguard` plus `tcpdump`, `wg show`.
- **Optional**: a second Android device or a Linux box to act as
  a known-good WireGuard client for comparison.  Generate fresh
  keys for it on the server (don't reuse the Chromebook's).

For most "what's my external IP" tests, use `ifconfig.me` or
`icanhazip.com`:
```
curl -4 ifconfig.me   # external v4
curl -6 ifconfig.me   # external v6
```

If the device lacks `curl` (most Android shells do), use this Go
binary one-liner from a Linux side instead, or open
`https://ifconfig.me/` in a browser inside that subsystem.


---

## Phase A — Verify the foundations

These tests pin down what we *think* we know.  If any answer
contradicts current assumptions, stop and re-evaluate before
running the rest.

### A1. ARC really uses the tunnel for v6

**Setup:** VPN up.  From ARC shell (`adb shell`):

```
# Step 1: Confirm v6 transport works through the tunnel
nc -6 2607:f8b0:4005:80b::200e 80 < /dev/null
# (Send: `GET / HTTP/1.0\r\nHost: ipv6.google.com\r\n\r\n` interactively
# if shell tools don't allow piping)
```

Then verify the path actually goes through wgrtc, not via cellular
directly:

```
# Step 2: VPN-side server tcpdump for the conversation
# On server, in another terminal:
sudo tcpdump -ni any 'udp port 22111' -t -v  # capture WG-encapsulated traffic
# OR
sudo tcpdump -ni wg0 'ip6'                   # the unencapsulated inner v6
```

Then on the Chromebook ARC shell:
```
# Issue an outbound v6 ping or TCP connect that should traverse the tunnel
nc -6 2606:4700:4700::1111 53 < /dev/null    # Cloudflare v6 DNS port 53
# OR
ping6 -c3 2606:4700:4700::1111               # if available
```

**Expected if v6 actually traverses the tunnel:**
- tcpdump on `wg0` shows v6 packets with source
  `fd00:a771:c05:80::6` going to the destination.
- tcpdump on `any udp/22111` shows WG-encapsulated traffic at the
  same time.

**Expected if ARC's v6 bypasses the tunnel:**
- tcpdump on `wg0` shows nothing for this destination.
- tcpdump on `any udp/22111` may show some keepalive traffic but
  not the burst.
- The packets went out the cellular path directly.

**Why this matters:** if ARC v6 *also* bypasses the tunnel, our
working hypothesis is wrong, the "v6 works in ARC" observation is
a false positive (just sees cellular v6), and the real story is
"v6 doesn't tunnel at all from ChromeOS."

### A2. External v6 IP from each subsystem

**Setup:** VPN up.  Capture the apparent external v6 from three
contexts:

```
# From ARC shell:
nc -6 ifconfig.me 80 -w 5
# (paste an HTTP/1.0 GET into the netcat)

# From crosh:
curl -6 ifconfig.me   # if curl is installed; else use the same nc trick
# or open https://ifconfig.me in the host Chrome browser

# From Crostini (lxc exec penguin bash):
curl -6 ifconfig.me
```

Compare against the **same test with the VPN down**.

**What this tells us:**
- If ARC's external v6 differs between VPN-up and VPN-down →
  tunnel carries v6 for ARC ✓ (current hypothesis confirmed).
- If ARC's external v6 is the *same* both ways → ARC's v6
  bypasses the tunnel.  Big finding.
- The expected v6 routed through the tunnel would be whatever
  v6 prefix your home Sonic connection has (after the server's
  NAT66).  Cellular-direct v6 would be a T-Mobile prefix
  (`2607:fb90:...`).

### A3. Internal-LAN ULA from each subsystem

**Setup:** VPN up.  Try reaching a v6 ULA that only your home LAN
knows about:

```
# From ARC shell:
ping -c3 fd00:a771:c05::101    # router container's v6
nc -6 fd00:a771:c05::103 22111 -w 3 < /dev/null  # wg server's WG port

# From crosh:
ping fd00:a771:c05::101

# From Crostini:
ping fd00:a771:c05::101
```

**Expected if tunnel works for that subsystem:**
- ARC: should reach (cellular has no route to ULA).  Current
  hypothesis says yes.
- crosh: should reach, but it probably won't because `send()`
  fails.  Confirms the host-side gap.
- Crostini: "Network is unreachable" — confirms the bypass.

**What this tells us:** ARC v6 working AND ULA reachable from ARC =
hard confirmation tunnel carries v6 for ARC.  If ULA is unreachable
from ARC too, the tunnel is *not* carrying v6 anywhere and the
hypothesis collapses.

### A4. Server-side: confirm wgrtc peer is the one passing v6

**Setup:** VPN up.  On the server:

```
ssh root@wireguard
sudo wg show wg0 transfer    # check the rx/tx counters
# Then trigger v6 traffic from ARC:
#   nc -6 ifconfig.me 80 from ARC
# Re-run:
sudo wg show wg0 transfer
```

**What this tells us:** if the counters jumped for peer
`D9R7TXZj4qpVS2qgYZIL55rXimGZXHfXETymKwR95hc=` during the test,
v6 traffic from ARC was tunneled.  If only v4 counters moved or
nothing moved, v6 went out elsewhere.


---

## Phase B — Configuration variants

These tests probe whether wgrtc's specific VpnService.Builder
configuration is the issue.  Edit the tunnel in the wgrtc app and
re-test each variant.  Capture the result of A2 (external v6 from
each subsystem) for each.

For each variant, before retesting:
1. Disconnect.
2. Edit the tunnel.
3. Reconnect.
4. Run A2 + A3.

### B1. IPv6-only AllowedIPs

```ini
[Peer]
AllowedIPs = ::/0       # no v4 at all
```

**Expected if our diagnosis is right:** ARC sees v6 via tunnel,
v4 returns "no route to host" or routes via underlying network.

**Surprising outcomes worth investigating:**
- ARC's v6 starts working *better* — possible if having mixed v4+v6
  routes confuses ChromeOS Patchpanel.
- ChromeOS-host's v6 starts working — same hypothesis.
- Crostini's v6 starts using the tunnel — would tell us Crostini
  drops to "no v4, fall through to tun0 for v6."

### B2. AllowedIPs limited to the WG-side v6 LAN only

```ini
[Peer]
AllowedIPs = 10.10.80.0/24, fd00:a771:c05::/64
# (split-tunnel — only LAN traffic goes through)
```

**Why:** isolates "VPN claims to be v6 default" from "VPN handles
v6 LAN traffic."  If LAN v6 (`fd00:...`) is reachable from
Crostini under this config but not under full-tunnel, we learn
that ChromeOS DOES install VPN routes for explicit prefixes but
not for `::/0`.

### B3. /64 inner address instead of /128

```ini
[Interface]
Address = 10.10.80.6/32, fd00:a771:c05:80::6/64
# (or /96, or anything wider than /128)
```

**Why:** Android's VpnService.Builder.addAddress traditionally
expects host /32 (v4) or /128 (v6).  A /64 declares a whole subnet
on tun0 and may make the resolver think v6 is "more configured."
Worth one shot.

### B4. Explicit Builder.allowFamily(AF_INET6)

This requires a wgrtc code change — not user-runnable.  But on the
roadmap as something we could try if other variants give us a hint.
Builder.allowFamily(int) was added in Android API 21 and *might*
nudge ChromeOS into different forwarding behavior.

### B5. Global v6 prefix instead of ULA

If your server has a global v6 prefix it can NAT to (e.g., a
delegated /60 from Sonic), reconfigure the peer's inner v6 to
something in that prefix:

```ini
[Interface]
Address = 10.10.80.6/32, 2001:5a8:4cea:cc00:80::6/128
# (or whatever your delegated global prefix is)
```

**Why:** ChromeOS / Android may treat ULAs as "private, possibly
not real internet" and decline to use them for resolver
configuration.  A global prefix removes that ambiguity.

**Constraint:** the server's nft `addr2mark` map needs to know
this address, otherwise the wg-nat blackhole rule drops the
traffic.  Either temporarily widen the map for this test, or
have the server's masquerade rule already handle the prefix.


---

## Phase C — Native WireGuard comparison

This is the most informative comparison: same wg-quick config (with
fresh keys), tested against the **official WireGuard Android app**
from the WireGuard project (`com.wireguard.android`).  If v6 works
there from Crostini / ChromeOS-host, we have a wgrtc bug.  If it
fails there too, the issue is genuinely at ARC's VpnService / ARC
Patchpanel level.

### C1. Setup

1. On the server, add a fresh peer with new keypair and an unused
   inner v6 address (e.g., `10.10.80.22/32, fd00:a771:c05:80::22/128`).
2. Install the official WireGuard app on the Chromebook via Play
   Store.  Import the config with the new keys.
3. Tap Connect.

### C2. Repeat Phase A tests

Run **A1**, **A2**, **A3**, **A4** with the official WireGuard app
instead of wgrtc, and write down the outcomes.

**If v6 works from Crostini / ChromeOS-host under the official
client:**
- We have a wgrtc-side bug.  Compare `dumpsys connectivity` output
  for the official client's VPN network vs wgrtc's.  Look for
  differences in LinkProperties, Capabilities, DnsAddresses, Routes.
- The most likely diffs: Capabilities (`NET_CAPABILITY_VALIDATED`
  per family), DnsAddresses (proper v6 server pushed), or a Builder
  API call we're not making.

**If v6 fails the same way:**
- The issue is at the ARC / Patchpanel / VpnService layer, not
  wgrtc-specific.  Our diagnosis stands.

### C3. Cross-check on a different ARC build (optional)

If a second Chromebook is available with a different ChromeOS
milestone:
- Install official WireGuard there with the same config.
- Test v6 from ChromeOS-host.
- If it works on a different ChromeOS version, the bug is
  ChromeOS-side and version-specific.


---

## Phase D — Platform diagnostics

### D1. ChromeOS Patchpanel logs

Patchpanel logs into `/var/log/messages` or via the ChromeOS log
collector:

```
# From crosh:
shell                                              # ChromeOS shell (may require dev mode)
sudo grep -i 'patchpanel.*ipv6\|patchpaneld' /var/log/messages | tail -50
sudo grep -i 'patchpanel.*tun0\|VPN' /var/log/messages | tail -50
```

**What to look for:** explicit errors when the wgrtc VpnService
comes up that mention IPv6, route, neighbor, or tun0.  These would
be smoking-gun evidence of where the v6 path breaks.

### D2. chrome://net-internals → DNS

Open `chrome://net-internals/#dns` in the ChromeOS Chrome browser
with wgrtc VPN up.  Look at:
- "Resolver" / "Effective DnsConfig" — what DNS servers does
  ChromeOS think it has?
- "Servers" list — does it include the synthesized v6 DNS
  (`2606:4700:4700::1111`) we pushed?

**If our v6 DNS isn't in the list:** ChromeOS host's resolver is
ignoring our VpnService.Builder.addDnsServer call for v6.  That's
a Patchpanel propagation issue.

### D3. ChromeOS-host's real routing table

```
# From crosh: (you may need dev-mode shell)
shell
sudo ip -6 route show
sudo ip -6 rule list
```

**What to look for:**
- Does ChromeOS-host's main table have a v6 default via tun0,
  or via the cellular path?
- Are there policy rules that route specific traffic via tun0?
- Compare against the per-network table view we got from ARC
  shell (where table 1034 has tun0 routes).

### D4. ChromeOS milestone

```
# From crosh:
lsb_release -a
```

Record the ChromeOS milestone.  If we file an upstream bug it'll
matter; if we find others reporting the same issue on the same
milestone we can correlate.


---

## Phase E — Crostini-specific tests

### E1. Toggle "Crostini through VPN" setting

ChromeOS has a setting at:
```
chrome://os-settings/crostini
```

Look for a checkbox like "Allow Crostini to access VPN traffic"
or similar (wording varies by ChromeOS version).  Toggle it on,
reboot Crostini (or just the penguin container), retest.

```
# From Crostini after toggling:
ip -6 route show
ping -c3 fd00:a771:c05::101
curl -6 ifconfig.me
```

**Expected if the setting works:**
- v4 through tunnel from Crostini ✓.
- v6 may still not — confirms Patchpanel v6 limitation extends to
  Crostini routing.

### E2. Manual v6 route insertion in Crostini

```
# In penguin (as root):
ip -6 route add default dev eth0 metric 10  # or whatever
# Then test:
ping6 -c3 fd00:a771:c05::101
```

**Why:** Crostini's eth0 is bridged to ChromeOS-host's networking.
If a manual route forces v6 onto eth0, and ChromeOS-host's
networking faithfully forwards it via tun0, we should reach the
LAN.  If `send()` fails immediately, the limitation is
deeper than just "route table missing."

### E3. v6-only DNS via systemd-resolved

Crostini uses its own resolver, often `systemd-resolved`.  Override
the DNS server explicitly:

```
sudo resolvectl dns eth0 2606:4700:4700::1111
sudo resolvectl domain eth0 '~.'
getent ahosts ipv6.google.com
```

**What this tells us:** if AAAA records come back but ping fails,
the resolver is fine but the v6 transport is broken.  Disambiguates
DNS issues from transport issues from Crostini.


---

## Phase F — Long-shots that might reveal the true cause

### F1. Daemon-as-joiner from a Linux box

If you have a spare Linux machine, install the wgrtc daemon and
configure it as a joiner of the same tunnel (using fresh keys).
Test v6 through it.

**Expected:** v6 works fully — the daemon is just kernel WG and
isn't subject to ChromeOS / ARC / Patchpanel limitations.  This
isolates the issue as ChromeOS-specific rather than wgrtc-
protocol-level.

### F2. ChromeOS bug report

If Phase C shows the official WireGuard app has the same v6
issue:
- Open `chrome://flags` and look for v6 / VPN-related experimental
  flags.
- File at https://issues.chromium.org under the platform/networking
  component, citing the diagnostic fingerprints from the README's
  Known limitations section.  Reference the official WireGuard
  test result.

### F3. arc-networkd / patchpanel command-line tools

ChromeOS has CLI tools to inspect/manipulate ARC network state:

```
shell
dbus-send --system --print-reply --dest=org.chromium.PatchPanel \
  /org/chromium/PatchPanel org.chromium.PatchPanel.GetDevices
```

(Method names vary; check the dbus introspection.)  This may
expose ARC's network forwarding state in more detail than
`dumpsys connectivity`.

### F4. Pixel hotspot v6 prefix delegation type

`ip -6 addr show` on the Chromebook showed
`2607:fb90:9f8c:82f9:502c:e0ff:feb5:d2c4/64` — a /64 from a SLAAC RA.
But the Pixel may have a `/64` from T-Mobile that it then SLAAC-RAs
to the Chromebook, vs. a `/56` it delegates via DHCPv6-PD and
sub-allocates to Wi-Fi clients.  These have different routing
implications for downstream Crostini.  Check:

```
# On the Pixel:
adb shell ip -6 addr
adb shell ip -6 route
```

(Requires USB-debug-enabled or local Wi-Fi adb access on the
Pixel.  Don't bother if it's intrusive.)


---

## Reporting the findings

After running each phase, update this document in-place with the
**actual** results next to the expected ones.  Conclusions from
each phase should feed into a final "what we now believe" section
at the bottom, which then gets distilled into the README's
"Known limitations" entry.

If a single test contradicts the current hypothesis cleanly,
**stop and re-evaluate before running more tests** — there's no
point continuing if the foundation has shifted.
