# V6 Runbook — Validating IPv6 End-to-End

This is the procedure used to verify wgrtc's dual-stack support
during v0.2.6 release validation.  Run it on any new device or
network where you want to confirm IPv6 works for joiners and hosts
before relying on it.

## What "v6 works" means here

Three independent properties:

1. **Wire format.**  Enrolment payloads, candidate lists, and
   AllowedIPs entries carry both v4 and v6 addresses without
   silently dropping the v6 half.  Pinned by the V6.3 unit tests +
   the `HostNativeV6SelfLoopTest` instrumented test.

2. **Tunnel handshake.**  A joiner and host with dual-stack
   addresses complete a WireGuard handshake and can exchange
   packets in either family.  Pinned by `HostNativeV6SelfLoopTest`
   on emulator + ARC.

3. **Public-internet reach.**  The through-host forwarder relays
   TCP, UDP, ICMP, and ICMPv6 from the joiner to a real public v6
   destination, and the reply gets re-injected into the tunnel.
   This is the V6.H2b deliverable.  Validated below.

## Quick check (5 minutes, no app required)

The `tmp/v6probe/` directory contains a small Go binary that
exercises the same syscall paths V6.H2b's `dispatchPingV6` uses:
`icmpx.ListenPacket("udp6", "::")` for ICMPv6 SOCK_DGRAM, plus
plain `net.DialContext("tcp6", ...)` and `net.DialUDP("udp6", ...)`.

Build for the target ABI:

```bash
cd tmp/v6probe
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o v6probe-arm64 .
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o v6probe-amd64 .
```

Push to an Android device or Chromebook (ARC) and run as the
`shell` UID:

```bash
adb push v6probe-amd64 /data/local/tmp/v6probe
adb shell chmod 755 /data/local/tmp/v6probe
adb shell /data/local/tmp/v6probe
```

Expected output on a dual-stack network (one JSON line per probe,
times will vary):

```
{"probe":"info","detail":"v6probe — running ICMPv6/TCPv6/UDPv6 checks"}
{"probe":"icmp6","target":"2001:4860:4860::8888","ok":true,"latency":"7ms","detail":"peer=…"}
{"probe":"icmp6","target":"fd00:a771:c05::50:0","ok":true,…}
{"probe":"tcp6","target":"[2001:4860:4860::8888]:53","ok":true,"latency":"6ms","detail":"local=2001:…"}
{"probe":"udp6","target":"[2001:4860:4860::8888]:53","ok":false,"detail":"write-ok, read failed: … permission denied"}
```

Reading the output:

- `icmp6 ok:true` from the shell UID is the **load-bearing
  signal** — it means the unprivileged ICMPv6 socket Android grants
  to apps in `ping_group_range` is delivering packets to the public
  internet and getting replies back.  V6.H2b's `dispatchPingV6`
  takes the exact same path.
- `tcp6 ok:true` + a non-link-local `local=` address proves the
  device has a real public v6 GUA (not just a site-local) and that
  Android's connectivity manager is routing v6 outbound through
  the underlying network.
- `udp6` may show `permission denied` on the read — that's
  Android's sandbox blocking the shell UID from receiving replies
  to unicast UDP from some destinations, not a v6 problem.  Apps
  with normal manifest permissions don't hit this.

If `icmp6` and `tcp6` both succeed, the device is suitable for
V6.H2b regression testing.  Plug a real WireGuard tunnel in on top
(via the wgrtc app) and use the same probe binary as if you were a
joiner peer — that confirms the through-host forwarder relays the
traffic end-to-end.

## Environments known to work

- **ChromeOS ARC** (dev-mode Chromebook over `adb connect`): public
  v6 round-trip ~7 ms.
- **Stock dual-stack home network**: trivially works.

## Environments known NOT to work (and why)

- **Android Studio emulator (qemu-system-x86_64-headless)**: slirp
  inside the emulator binary always owns the guest's IP assignment
  and doesn't NAT outbound v6.  No flag bypasses this.  Even
  `/dev/net/tun` + a real Linux bridge to the LXC's upstream
  doesn't help — guest IPs still come from slirp.  Use ARC for v6
  validation, not the emulator.

- **IPv4-only test rigs**: `tcp6` will fail with "network is
  unreachable" because the kernel has no v6 default route.  Add
  `IPv6AcceptRA = true` to the device's network config (or
  equivalent) before assuming wgrtc is at fault.

## Production verification: full app loop

1. Boot a dual-stack daemon (`apt install ./wireguardrtc_*.deb` on
   a Linux box with both v4 and v6 LAN connectivity).  `wg show
   <iface>` should list both an `Address` and a v6 `Address` in
   `wireguardrtc.conf`.

2. Mint an enrolment for your phone (`sudo wireguardrtc
   --enroll-token "phone" --expires 600` or wormhole).  The
   resulting QR / wormhole payload includes a v6 `AllowedIPs`
   entry — verify with the app's "Show last invitation" action.

3. Bring the tunnel up on the phone.  Open
   [https://ipv6.icanhazip.com/](https://ipv6.icanhazip.com/) in
   the joiner's browser; it should return the **host's** public v6
   GUA, not the joiner's underlying network's GUA.  That proves
   v6 traffic is being NATted through the host's catchall
   forwarder.

4. From a shell on the joiner (Termux on Android, or `adb shell`
   on ARC), `ping6 google.com` should succeed.  That's V6.H2b's
   ICMPv6 echo path.

If step 3 fails: check the host's gvisor netstack actually got the
v6 address (`adb shell dumpsys connectivity | grep <iface>`).  If
step 4 fails: pull logcat with the `wgrtc-host-fwd` tag — the
heartbeat line shows `pingsSent` / `pingsRpld` / `unsupportedDrops`
which pinpoint where the v6 path is breaking.

## Where the code lives

- Daemon v6: `daemon/wireguardrtc` (V6.D1, V6.D3, V6.D4, V6.D5).
- Joiner v6: `android/app/src/main/kotlin/.../{JoinerVpnConfig,
  ConnectionRunner, MtuMath}.kt` (V6.A1, V6.A2, V6.A3).
- Host v6: `android/wgbridge_native/host_forwarder.go` (V6.H1,
  V6.H2, V6.H2b) and `android/app/src/main/kotlin/.../HostModeBackend.kt`.
- Enrolment wire format: `signalling/.../EnrollOkPlain.kt`,
  `daemon/wireguardrtc` (V6.3).
- ULA allocation: `HostSubnetAllocator.kt` (V6.2).

## What's deferred (known caveats)

These are documented in `ipv6-design.md` under the V6.H2b entry —
none affect normal use:

- IPv6 extension headers (Fragment, HBH) are dropped at the host
  forwarder.  Joiner kernels don't fragment ICMPv6 echoes; only
  bulk-UDP edge cases would hit this.
- ICMPv6 error message translation (Packet Too Big → joiner) is
  silent-dropped.  Breaks PMTU-D from the joiner; load-bearing for
  large UDP workloads only.
- The emulator slirp limitation noted above.
