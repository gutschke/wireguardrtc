# WireGuard Runtime Architecture

**Status:** authoritative as of (2026-05-10).
**Audience:** future engineers (including future-me) who need to
understand *why* the app's WireGuard plumbing looks the way it
does, swap the WG implementation for a different fork, or — in an
emergency — undo and put wireguard-android back.

Read this **before** touching anything related to WG tunnels,
VpnService, JNI loading, or the `wgbridge_native/` Go module.

---

## TL;DR

There is exactly one WireGuard runtime in the APK now:
`libwgbridge_native.so`, a cgo + `//export` build of upstream
[`golang.zx2c4.com/wireguard`](https://git.zx2c4.com/wireguard-go).
Both hosting and joining go through the same Go module, the same
JNI surface (`com.gutschke.wgrtc.data.WgBridgeNative`), and the
same Kotlin wrapper (`RealWgBridgeBackendNative`). The boundary
between Kotlin and the Go runtime is the **UAPI text protocol** —
the same wire format `wg(8)` speaks. Everything else is hidden
behind that boundary.

This is a deliberate, hard-won simplification. The road there
involved deleting two libraries (`gomobile-bind wgbridge.aar` and
`wireguard-android:tunnel`), three workaround layers
(`GoRuntimeGuard`, `WgSocketBinder` , the F-fix series),
and roughly 1000 lines of conditional code.

Skip to **§6 (Protocols handled)** for the IP-protocol matrix
(what works through the tunnel, what doesn't). Skip to **§8
(Rollback recipe)** if wireguard-android needs to come back.
Skip to **§9 (Swapping the WG backend)** if you're evaluating
amneziawg / wg-obfs / BoringTun.

---

## 1. Current architecture

```
┌────────────────────────────────────────────────────────────────────┐
│ Android app process (com.gutschke.wgrtc.debug) │
│ │
│ ┌────────────────────────────────────────────────────────────┐ │
│ │ Kotlin │ │
│ │ ┌──────────────────┐ ┌──────────────────┐ │ │
│ │ │ JoinerVpnService │ │ ModeAHostBackend │ │ │
│ │ │ (TUN-fd path) │ │ (gvisor netstack)│ │ │
│ │ └────────┬─────────┘ └────────┬─────────┘ │ │
│ │ ↓ ↓ │ │
│ │ ┌────────────────────────────────────────────┐ │ │
│ │ │ RealWgBridgeBackendNative │ │ │
│ │ │ (handle-based JNI wrapper) │ │ │
│ │ └────────────────────┬───────────────────────┘ │ │
│ │ ↓ │ │
│ │ ┌────────────────────────────────────────────┐ │ │
│ │ │ WgBridgeNative (external native fun) │ │ │
│ │ └────────────────────┬───────────────────────┘ │ │
│ └───────────────────────│─────────────────────────────────────┘ │
│ ↓ JNI │
│ ┌────────────────────────────────────────────────────────────┐ │
│ │ libwgbridge_native.so (cgo c-shared library) │ │
│ │ ┌────────────────────────────────────────────┐ │ │
│ │ │ jni_android.c Java_… → //export shims │ │ │
│ │ ├────────────────────────────────────────────┤ │ │
│ │ │ api.go //export wgbridgeNew, wgbridge- │ │ │
│ │ │ ConfigureUAPI, wgbridgeSnapshot- │ │ │
│ │ │ UAPI, wgbridgeClose, … │ │ │
│ │ ├────────────────────────────────────────────┤ │ │
│ │ │ golang.zx2c4.com/wireguard (vendored) │ │ │
│ │ │ device + conn + tun.netstack │ │ │
│ │ ├────────────────────────────────────────────┤ │ │
│ │ │ logger_android.go wg-go logs → │ │ │
│ │ │ __android_log_write │ │ │
│ │ └────────────────────────────────────────────┘ │ │
│ └────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────┘
```

The JNI surface (see `WgBridgeNative.kt`):

**Bridge lifecycle**

| Method | Purpose |
|---|---|
| `nativeVersion(): String` | Build identifier + wireguard-go commit; round-trip sanity. |
| `nativeNew(localAddr, mtu, listenPort): Int` | Open a *host* bridge with gvisor userspace netstack. |
| `nativeNewWithTunFd(fd): Int` | Open a *joiner* bridge over an existing kernel TUN fd (from `VpnService.Builder.establish()`). |
| `nativeConfigureUAPI(handle, uapi): Int` | Apply a UAPI text document. |
| `nativeSnapshotUAPI(handle): String?` | Dump current state as UAPI text (`wg show … dump` equivalent). |
| `nativeClose(handle)` | Tear down the bridge. Idempotent. |

**Host-side TCP/UDP listeners** (host bridges only — operates on the gvisor netstack)

| Method | Purpose |
|---|---|
| `nativeListenTcp(handle, port): Int` | Open a TCP listener on `0.0.0.0:port`. Each accept fires `onTcpAccept(listenerId, connId, peerAddr, listenAddr)`. |
| `nativeListenUdp(handle, port): Int` | Open a UDP socket. Each inbound datagram fires `onUdpDatagram(listenerId, peerAddr, listenAddr, byte[])`. |
| `nativeDialTcp(handle, "host:port"): Int` | Outbound TCP from inside the netstack (test affordance). |
| `nativeTcpRead(connId, buf, len): Int` / `nativeTcpWrite(connId, buf, len): Int` / `nativeTcpClose(connId)` | Per-connection I/O. |
| `nativeUdpSendTo(listenerId, "host:port", buf, len): Int` | Outbound UDP via the listener socket. |
| `nativeCloseListener(listenerId)` | Stop accept / recv loop. Doesn't affect already-accepted TCP conns. |

The accept / recv loops dispatch to Java via C-side
AttachCurrentThread → CallStaticVoidMethod → DetachCurrentThread.
The C dispatcher is registered in `JNI_OnLoad`. Per-listener
routing on the Kotlin side lives in `TcpListenerRegistry` /
`UdpListenerRegistry`.

The Go side keeps state in `int32 →` map structures
(bridges + listeners + tcp conns). **Java never touches a Go
pointer.** That single design choice is what makes the build
robust — see §5 (gomobile pitfalls).

### 1.1 Why userspace NAT (not AF_TUN + raw sockets)

A natural-looking design for "phone-as-gateway" tethering would
be:

1. Read inbound IP packets from the WG-tunnel side.
2. Parse, rewrite source IP/port to the phone's outbound address.
3. Re-emit on the phone's physical interface using a raw socket.
4. Reverse the rewrite on the return path.

This is impossible on unrooted Android, and architecturally less
desirable than what we do.

**Impossible:** emitting raw IP packets to the physical network
requires `CAP_NET_RAW` or root. Unprivileged apps can't open
`AF_PACKET`, can't bind a `SOCK_RAW` socket, and the only
"packet-shaped" surface available is the VpnService TUN fd —
which only delivers packets *into* the device (the inverse of
what we want). `IP_TRANSPARENT` is similarly root-only.

**Architecturally less desirable** even if it were possible:

- **TTL invisibility.** When the phone is the *originator* of an
 ordinary application-uid socket, the outbound packets have TTL
 = 64 (Android's default). A NAT-rewrite approach would copy
 the joiner's TTL minus 1, giving 63 — the classic tethering
 tell that carriers grep for to enforce hotspot data plans.
 Our approach naturally defeats this; an AF_TUN-NAT approach
 would have to manually rewrite TTL to 64, which is detectable
 in its own way (no real Android device emits 64 from a forwarded
 path).
- **Per-app routing alignment.** Android's connectivity stack
 associates each socket with a uid for accounting + per-uid
 routing policies. When the phone's apps share Wi-Fi+cellular
 the way ordinary apps do, the sockets we open inherit those
 rules. An AF_TUN-NAT path would bypass uid accounting and
 bypass any per-uid policies (good for invisibility, bad for
 diagnostics and for honest cellular usage tracking).
- **No iptables / mangle dependency.** We don't need NETFILTER
 rules of any kind. The Go-side gvisor netstack does all
 flow-state work in userspace; the Kotlin-side
 `TcpFlowForwarder` does the bidirectional byte pump.
- **Application-layer awareness.** When the per-flow proxy
 fails to open the upstream socket, we can return an
 intelligible error. An AF_TUN-NAT can only respond with
 ICMP unreachable + a TCP RST and hope the client interprets
 it usefully.

The cost we pay for the userspace approach: **CPU + memory
overhead vs. kernel TCP**. Each forwarded flow runs a Go
goroutine pair plus a Kotlin coroutine pair plus an OS socket;
throughput is bounded by gvisor's TCP implementation rather than
the kernel's. On a Pixel-class device this is comfortably above
typical browsing rates; for sustained high-throughput (4K video,
large file transfers) the ceiling needs measurement. If we ever
need to exceed that ceiling, the architectural answer is to ask
the user to root the device and switch to a kernel-level
implementation — not to bolt one onto this design.

Forward compatibility note: the "cascade through another WG
tunnel" use case (joiner → phone-as-gateway → outer corporate
WG → public internet) preserves the userspace approach
unchanged. The phone's per-flow outbound socket just happens to
travel through another WG tunnel before reaching the public
internet, and that outer tunnel is its own Bridge instance with
its own netstack. No changes to the NAT data path required.

### Two consumers, one runtime

- **Host mode** (`ModeAHostBackend`): runs a WG endpoint on a real
 UDP port + a gvisor netstack at the WG-side IP. Peers see a
 normal `:51820` UDP service and the gvisor stack responds to
 ICMP/TCP/UDP at `10.99.0.1`. No `VpnService` consent dialog on
 the host phone. Reconfigure is in-place (`IpcSet`).
- **Joiner mode** (`JoinerVpnService` + `JoinerWgRunner`): the app
 is the WG client. Android `VpnService.Builder.establish()` opens
 a TUN, the fd is handed to `wgbridgeNewWithTunFd`, and
 wireguard-go encrypts outbound packets + decrypts replies. The
 app is exactly *one* VpnService — there is no separate
 `GoBackend$VpnService` anywhere.

### What's NOT in the architecture (any more)

- ❌ `wireguard-android:tunnel` AAR
- ❌ `com.wireguard.android.backend.GoBackend`
- ❌ `com.wireguard.android.backend.Tunnel` interface
- ❌ `com.wireguard.config.Config` parser
- ❌ The gomobile-built `wgbridge.aar` (`libgojni.so` per ABI)
- ❌ `GoRuntimeGuard` (no second runtime to guard against)
- ❌ `HostingMode` enum (no vs there is only one)
- ❌ `JoinerBackend` enum (no LEGACY_GOBACKEND vs WGBRIDGE)
- ❌ `WgSocketBinder` ( reflection — was always a documented dead end)
- ❌ `RealTunnelEndpointController` (legacy joiner controller; replaced by `WgBridgeTunnelEndpointController`)

---

## 2. Why we left wireguard-android (the legacy host path)

`wireguard-android:tunnel` is the upstream WG library for Android.
It works fine for **client mode** — it's the same library the
official WireGuard app ships. We used it for both host and joiner
through of the project, and *for joiner it's fine*. The
problem is host mode.

**Symptom:** with a host tunnel UP under `GoBackend`, joiners
complete the handshake (the host phone logs the v4 receive routine
starting, the peer creation, the handshake-init RX), but pings to
the host's WG-side IP (10.99.0.1) never get a reply. Packet
counters never tick. Same WiFi, same subnet, no firewall, no
mystery — the joiner's `tun0` happily transmits, the host
hardware happily receives, wireguard-go on the host happily
decrypts, then the decrypted ICMP echo lands on the host's `tun0`
and **nothing on the host phone responds.**

**Root cause:** `wireguard-android`'s `GoBackend$VpnService`
brings up a *real* Android `VpnService`. Android's VpnService TUN
is a **forwarding** TUN — it captures the app process's *outbound*
packets so they can be encrypted, but it does **not** deliver
*inbound* packets to local-process sockets. The TUN is wired into
Android's per-uid routing tables specifically to push packets *out*
of the app. Inbound from the WG tunnel has nowhere to go.

This is not a bug in wireguard-android; it's the design contract
of `VpnService`. It's a fine fit for *being a VPN client*. It's
the wrong shape for *running a server*.

**Fix:** for host mode, run wireguard-go in *userspace* with its
own gvisor netstack (the `wireguard/tun/netstack` subpackage). The
netstack does respond to ICMP. The netstack accepts userspace TCP
`Dial` and UDP `WriteTo`. This is the path we now use
unconditionally.

(For the curious: amneziawg-android, mullvad-android,
wireguard-rs-android — all the apps that work *as a server* on
Android — also bypass `GoBackend` and embed wireguard-go directly.
This is a well-known limitation.)

---

## 3. Why we left gomobile-bind (the legacy joiner path)

`gomobile bind` generates a JVM-compatible Java surface from
exported Go functions. It's the canonical way to ship a Go library
to Android. We initially used it for `wgbridge.aar` so the Kotlin
side could call `Wgbridge.OpenFd(...)` and friends as plain Java
methods.

The build pipeline worked. The library loaded. JNI calls succeeded.
The first call to `dev.IpcSet(...)` *also* succeeded. But on the
**first handshake**, when wireguard-go fires its first callback
from a Go goroutine back into the runtime, the process died with:

```
fatal error: runtime.bulkBarrierPreWrite: unaligned arguments
```

This was the F-fix series' nemesis. After much debugging (see
[`wireguard-go TUN-fd alignment bug`](../../../.claude/projects/-home-markus-src-wireguardrtc/in the project memory), the diagnosis was:

- `gomobile bind`'s generated marshalling layer copies Go-managed
 struct values across the JNI boundary in a way that violates Go's
 pointer-alignment invariants.
- The Go runtime's write barrier (`bulkBarrierPreWrite`) checks
 pointer alignment on every cross-frame write that touches GC'd
 memory.
- Once a misaligned pointer enters Go's view, the *next* GC scan
 or write barrier dies.
- This is independent of Go version, NDK version, ABI, device — it's
 a structural mismatch between gomobile-bind's calling convention
 and the current Go runtime.

**Workarounds we tried that didn't work:**
- Pinning Go 1.21 / 1.22 / 1.23 / 1.24 (same panic at every
 version we tested).
- Disabling gomobile's GC hints (no public API to do this).
- Wrapping all bind calls in a single `synchronized` block (the bug
 is on a different goroutine — the wireguard-go handshake worker).
- Two parallel processes (would have worked but adds IPC and
 multi-process VpnService complexity we didn't want).

**Fix:** stop using gomobile. Hand-write JNI:
- Go side: declare functions with `//export wgbridgeNew` etc., a
 single trivial `main()`, `-buildmode=c-shared` produces a
 `.so` + a generated `.h` we ignore.
- C side (`jni_android.c`): one tiny `Java_<class>_<method>`
 function per Go export. The C functions handle `jstring → C
 string → Go string` conversions explicitly. Pointers across the
 JNI boundary are always `jint` handles into a map. Go pointers
 never leak.

The cgo build pipeline is `wgbridge_native/build.sh`. Pattern
lifted verbatim from wireguard-android's `tools/libwg-go`.

**Validated:** `WgBridgeNativeHandshakeTest` (emulator) runs an
end-to-end handshake against a kernel-WG server in 0.8s. Android phone
field test 2026-05-10 logged a full pingable tunnel under both
host () and joiner (WGBRIDGE) flows.

---

## 4. The UAPI boundary

The single most important architectural choice — the one that
makes everything else simple — is that the **Kotlin/Go boundary
speaks WireGuard's UAPI text protocol**, not Java types.

UAPI is the text format `wg(8)` uses to communicate with the kernel
WG module (over `/var/run/wireguard/<iface>.sock` on Linux).
Every WireGuard implementation speaks it. Example:

```
private_key=8d4...
listen_port=51820
replace_peers=true
public_key=aa3c...
endpoint=192.0.2.1:51820
persistent_keepalive_interval=25
replace_allowed_ips=true
allowed_ip=10.99.0.1/32
```

We render this string in Kotlin (`WgQuickUapi.kt`), hand it to Go
via `nativeConfigureUAPI(handle, uapi)`, and Go's
`device.IpcSet(uapi)` does the parse + apply. To read state back,
`nativeSnapshotUAPI(handle)` returns a UAPI dump (same shape) that
`UapiStatsParser.kt` re-parses into a Kotlin `UapiStats`.

**Why this matters:** the Kotlin side has zero knowledge of
wireguard-go's internals. No struct copies, no callbacks (other
than the Android log forwarder), no opaque handles for peers or
devices. A handle is just an `int`. The Kotlin code could, in
principle, target *any* WG implementation that speaks UAPI — see
§8.

**What's NOT in UAPI (and where it lives):**
- `Address`, `MTU`, routes — applied at TUN-fd creation time by
 Android `VpnService.Builder` (joiner) or at netstack creation
 time by `netstack.CreateNetTUN` (host).
- DNS — `wg-quick`'s `DNS = ...` is a userspace resolver hint and
 we deliberately don't honour it. Apps inside a joiner tunnel
 use the OS's DNS for whatever network they're on.
- `PreUp` / `PreDown` / `PostUp` / `PostDown` — wg-quick script
 hooks. Not applicable on Android.

The `WgQuickUapi.render(wgQuick)` parser is the only place we
translate the human-friendly wg-quick syntax (`Endpoint = host:port`,
base64 keys, comma-separated AllowedIPs) into UAPI's
machine-friendly form (`endpoint=host:port`, hex-encoded keys, one
`allowed_ip=` line per CIDR).

---

## 5. Pitfalls (and how we solved them)

A running list of every non-obvious gotcha we hit. Read these
before debugging WG plumbing; you've probably already hit at
least one of them.

### 5.1 Don't trust the emulator's inbound port-forwarding for host-mode tests

QEMU's slirp NAT *does* forward inbound packets to the emulator's
`:51820`, but its reverse mapping for the response is incomplete:
when wireguard-go responds (`src=:51820`), slirp randomises the
**outbound source port**. Bridges that use `udp.connect((host,
port))` then filter responses out as wrong-source.

Even with an IP-only filter, slirp may drop responses entirely for
inbound-forwarded UDP flows. So the emulator + sandbox-bridge
`HostNativeHandshakeTest` we briefly added was unreliable. We
removed it.

**For host-mode validation on the emulator,** use
`HostNativeSelfLoopTest` — two `wgbridge_native` instances inside
the same process, talking via 127.0.0.1. No slirp involvement.
Handshake completes in <5 ms.

(See [`feedback_emulator_slirp_inbound`](../../../.claude/projects/-home-markus-src-wireguardrtc/memory/feedback_emulator_slirp_inbound.md).)

### 5.2 `IpcSet` is a merge, not a replace

Without explicit `replace_peers=true` / `replace_allowed_ips=true`
lines, `IpcSet` merges the new state into the old. That means:
- Revoking a peer: just `remove=true` on its `public_key=` block.
- *Replacing* the peer set: `replace_peers=true` *first*, then the
 surviving `public_key=` blocks. Without that line, removed peers
 linger.

`WgQuickUapi.render` emits both replace lines unconditionally.
Reconfigure with the full intended state and you're safe. (This
was the bug source.)

### 5.3 Closing + reopening a `Bridge` in one process panics

Closing wireguard-go's `device.Device` and constructing a new one
in the same process trips an alignment panic at the bulkBarrier
check (similar shape to the gomobile bug but a different
codepath). We dodge it via a **pause/resume** pattern: instead of
`Bridge.Close()`, push UAPI `listen_port=0\nreplace_peers=true\n`
to drop all peers and unbind. To resume, push the real config
back.

`ModeAHostBackend.stop()` does pause; `ModeAHostBackend.teardown()`
does close. The view-model prefers stop. See `HostModeRunner.pause`.

### 5.4 Hostnames in `Endpoint = host:port`

wireguard-go resolves hostnames itself inside `IpcSet`. Don't
pre-resolve in Kotlin — DNS at app-startup time gets cached and
stale. Just pass the wg-quick text through.

### 5.5 LAN race winners must not be persisted

When the ConnectionRunner picks a same-subnet IP as the race winner,
that address is environment-specific. Persisting it to disk
breaks the tunnel after the user changes networks (the persisted
LAN address is unreachable from the new network).

`shouldPersistRaceWinner(egressInterface)` returns true only for
universal (public/STUN) addresses. Pinned by
`ShouldPersistRaceWinnerTest`. This was a deadlock source during
the 2026-05-08 debug session.

### 5.6 Logging from cgo on Android goes nowhere by default

Go's default `log` package writes to stderr. On Android stderr is
`/dev/null`. wg-go's `device.Logger` defaults to that. Solution:
`logger_android.go` (built with `//go:build android`) wires a
custom logger backed by `__android_log_write`. Now `Sending
handshake response` lines actually appear in `adb logcat -s
wgbridge_native`. Indispensable for debugging real-device issues.

(The non-android fallback `logger_other.go` keeps `go build` happy
on the dev host. Filename-based build constraint — the `_android.go`
suffix matches Go's `GOOS=android`.)

### 5.7 `kernelConfigStream()` is *not* the same as `configText`

For HOST_MODE tunnels, `configText` is the `[Interface]` block
only — the `[Peer]` entries live in `hostMode.enrolledPeers` and
must be rendered into a kernel-shaped config by `renderWgConfig`.
Skipping that step is the bug (host came up with zero peers,
silently dropped every joiner's handshake init).

The contract: any code path that wants to bring a tunnel up via
UAPI **must** go through `kernelConfigStream()` or equivalent
(e.g. `Tunnel.toRunnerConfig().renderUapi()`). Pinned by
`RenderWgConfigContractTest`.

### 5.8 Don't try `Network.bindSocket()` on a protected WG socket

`VpnService.protect(fd)` excludes the socket from the VpnService's
own routing. The Network handle's `bindSocket` then returns EPERM
on protected sockets (Android 10+). The hotspot guarantee is held
by **same-subnet ranking** + **strict mode no-fallthrough**, not by
egress binding. The `WgSocketBinder` reflection ladder was a
documented dead end and was deleted in .

### 5.9 Go's `package main` requirement for c-shared

`-buildmode=c-shared` requires `package main` and a (possibly empty)
`func main()`. We have one. Don't change `wgbridge_native/api.go`'s
package declaration.

### 5.10 Debugging a Go panic inside the .so

When the .so panics on the device the tombstone only shows one
frame (`runtime.raise.abi0+33`). To find the actual Go function
that crashed:

 1. Rebuild with symbols: `WGRTC_DEBUG_BUILD=1
 ./wgbridge_native/build.sh`. This drops `-trimpath` and
 `-buildid=`.
 2. From the tombstone, note the offset of `runtime.raise.abi0`
 in the `.so` (e.g., `pc 00000000001b7121`).
 3. Compute load base: tombstone's `rip` minus that offset.
 4. From the `E Go` line in logcat: `panic: ... pc=0xXXXXXXXX`.
 Subtract the load base to get the panic PC's `.so` offset.
 5. Run `llvm-addr2line -e build/jni/<abi>/libwgbridge_native.so
 -f -C -i <offset>`. The result names the Go function +
 line that panicked.

The whole loop is ~10 minutes once the debug build is in place.
The era addrlines are how we found 's
`r.ID() after r.Complete()` bug.

### 5.11 Filename-based build constraints, not import-side `_test` suffixes

Go's filename-based build tags are the cleanest way to gate cgo
code at the source level. We use:
- `logger_android.go` → built for Android only.
- `logger_other.go` → built for everything except Android.
- `jni_android.c` → built for Android only (`#include <jni.h>` is
 unavailable on the host).

---

## 6. Protocols handled (and not handled)

The host's gvisor netstack handles a finite set of IP protocols.
The userspace-NAT path explicitly forwards a smaller set.
Everything else is silently dropped at gvisor's IP layer (no
data corruption, no leakage to a different egress — just
black-holed).

| Proto # | Name | gvisor native | Our forwarder | Result through tunnel |
|---:|---|---|---|---|
| 1 | ICMPv4 (echo + errors) | echo-reply for host's WG-side IP | ** diagnostic + through-host** | pings to *any* IPv4 address work end-to-end — `10.99.0.1` via gvisor auto-reply, `1.1.1.1` via the host-forwarder (see §6.1) |
| 2 | IGMP | no | no | dropped silently |
| 6 | TCP | yes | ** catchall + through-host** | NAT'd via OS socket for *any* dst — local-dst routed by gvisor directly, non-local-dst caught via the host forwarder's temp-local-address trick (see §6.1) |
| 17 | UDP | yes | ** catchall + through-host** | same shape as TCP |
| 41 | IPv6-in-IPv4 (6to4) | no | no | dropped silently |
| 47 | GRE (PPTP, OpenVPN bridge, ...) | no | no | dropped silently |
| 50 / 51 | ESP / AH (IPsec) | no | no | dropped silently |
| 58 | ICMPv6 | echo-reply subset | no | similar to ICMPv4 but no diagnostic helper yet |
| 89 | OSPF | no | no | dropped silently |
| 132 | SCTP (WebRTC SCTP-over-UDP rides UDP and works) | no | no | raw SCTP dropped |
| all others (~250) | various | no | no | dropped silently |

**IPv6:** gvisor netstack supports IPv6 TCP/UDP natively, but the
host bridge currently only binds an IPv4 address. Lighting up
IPv6 is mostly a configuration change in `nativeNew` —
deferred until there's a real-world need.

**PMTU caveat.** The user's PMTU concern is addressed primarily
by **MSS clamping** at (TCP segments never exceed `wgMtu - 40`
bytes, so no ICMP-Frag-Needed feedback is needed for TCP). For
UDP, PMTUD via ICMP would require reading ICMP errors from raw
sockets (`CAP_NET_RAW`, root-only on Android). Practical
mitigation: applications fragment their own UDP payloads, and
the WG outer socket has `DF=0` so downstream routers can
fragment if needed.

**ICMP / through-host ( + ).** Two complementary helpers:
- `wgbridgePingV4` (`icmp.go`) — one-shot diagnostic ping from the
 app down the netstack, used by the in-app diagnostics screen.
- `wgbridgeInstallHostForwarder` (`host_forwarder.go`) — the
 full-tunnel through-host path; installed automatically by
 `ModeAHostBackend` when host-mode tunnels start. Joiner pings
 to any address (1.1.1.1, 8.8.8.8) traverse the host's WG tunnel
 + the host's real network and return. See §6.1 for the design.

**Operational visibility.** gvisor exposes per-protocol drop
counters via `Stack.Stats()`. Surfacing those through a
diagnostic UAPI snapshot is on the roadmap so a power user can
see "your tunnel dropped 14 GRE packets in the last hour."

### 6.1 Through-host forwarding (the host forwarder)

**The gap (before ).** A joiner with `AllowedIPs = 0.0.0.0/0`
routes all of its traffic through the WG tunnel, expecting the
host to NAT it out the phone's normal egress. But gvisor's
catchall handlers (`tcp.NewForwarder`, `udp.NewForwarder`, and
ICMP's internal handler) only fire for packets whose destination
IP is *locally assigned* to the netstack. Packets to non-local
IPs (1.1.1.1, 8.8.8.8, anything outside the WG-side subnet) get
dropped at gvisor's IP layer because forwarding isn't enabled
and there's no matching local address.

**The Option B fix (`host_forwarder.go`, validated 2026-05-10
on Android phone).**

1. Add a second `channel.Endpoint` (NIC2) to the bridge's stack;
 install routes so the WG-side subnet stays on NIC1 and the
 default route points at NIC2. Enable IPv4 forwarding.
2. A goroutine reads packets that gvisor forwarded onto NIC2's
 outbound queue (TTL already decremented, IP checksum already
 recomputed) and dispatches per IP protocol:
 - **ICMP echo** → real ICMP via
 `golang.org/x/net/icmp.ListenPacket("udp4")` (Linux
 unprivileged `SOCK_DGRAM/IPPROTO_ICMP`), synthesize an
 echo-reply on success, `inEp.WritePackets` it into NIC1.
 `WritePackets` is the load-bearing choice — it bypasses
 netstack routing entirely so the `forwardUnicastPacket →
 ErrSameInterface` anti-loop check (`pkg/tcpip/network/ipv4/ipv4.go`)
 doesn't drop the reply. The joiner's original ICMP `ident`
 must be preserved when synthesizing the reply — the kernel
 rewrites it on the unprivileged socket, so the value
 returned by `ReadFrom` is the rewritten one, not the joiner's.
 - **TCP / UDP** → register dst as a *temporary local address*
 on NIC1 via `AddProtocolAddress(... Temporary: true)`, clone
 the bytes, `inEp.InjectInbound`. On the next round gvisor
 sees dst as local + delivers to the transport layer where
 `tcp.NewForwarder` / `udp.NewForwarder` (/ catchalls)
 fire. Existing handlers do real OS-socket NAT. Subsequent
 packets in the same flow arrive at NIC1 directly (dst is
 already temp-local), bypassing NIC2 entirely — so the
 redirect only fires once per new flow.

**Validation** (`HostModeForwarderE2ETest`, 2026-05-10):
- Android phone + Cloudflare WiFi: 5/5 ICMP pings to 1.1.1.1 (16–24 ms RTT);
 TCP `1.1.1.1:80` returns `HTTP/1.1 301 Moved Permanently`;
 UDP `1.1.1.1:53` works (flaky upstream — Cloudflare anycast DNS
 occasionally drops single-shot queries).
- Forwarder counters confirm the architecture: one temp-local-address
 entry created (TCP), reused by UDP (so `udpRedirs=0` despite UDP
 reaching the catchall — UDP went via NIC1 directly because dst was
 already temp-local from TCP).

**Why not promiscuous mode (the failed v2 alternative).**
`Stack.SetPromiscuousMode(NIC1, true)` empirically breaks gvisor's
auto-reply for the host's *real* WG-side IP — even with a custom
`SetTransportProtocolHandler` for ICMPv4 the handler was never
invoked AND auto-reply also didn't fire. Bisected: promiscuous
mode alone breaks local-IP echo reply; root cause never pinned
down (suspected: gvisor's transport demuxer's `deliverPacket`
returns `handled=true` from some endpoint that promiscuous mode
implicitly registers, short-circuiting both paths). Temp-local-
address trick achieves the same effect without breaking auto-reply
for actually-local addresses.

**Known limitations.**
- **Memory growth.** Temp addresses accumulate over the bridge's
 lifetime — one per distinct external destination the joiner
 ever connects to. In practice bounded by the user's browsing
 pattern (low hundreds of dsts). An LRU eviction pass would
 cap this; not blocking.
- **IPv4 only.** IPv6 path is parallel-implementable but the
 bridge currently only binds an IPv4 WG-side address (§6 IPv6
 note).
- **ICMP errors (type 3/11/12) not surfaced upstream.** The
 forwarder only handles `Echo` / `EchoReply`. Path-MTU
 discovery via ICMP-Frag-Needed isn't end-to-end (MSS clamping
 at handles the common TCP case).

---

## 7. The migration trail (commits behind us)

For anyone tracing how we got here. Not exhaustive — just the
load-bearing checkpoints.

| Phase | Highlight |
|---|---|
| | Initial wgbridge.aar prototype (gomobile-bound). VpnService skeleton with protect callback. |
| | TCP / UDP forwarders for the host's cleartext side. |
| | Host mode switched to userspace `UserspaceWgEndpoint`. |
| | wgbridge JNI startup probe DISABLED — feared dual-runtime conflict (turned out to be gomobile alignment). |
| | DOWN→UP cycle suppression during internal reconfigure. |
| | HOST_MODE connect ignored enrolled peers (the "no traffic" bug). |
| | In-process GoRuntimeGuard tracking via `AtomicBoolean` (replaced fragile `/proc/self/maps` scan). |
| | Pause/resume bridge instead of close+reopen (avoids `bulkBarrierPreWrite` panic). |
| | wgbridge TUN-fd joiner path built incrementally. |
| | cgo + `//export` skeleton spike. |
| | **Decisive test passed** — cgo path completed a handshake against a real WG peer. |
| | Full wgbridge surface ported to `//export`. |
| | Joiner default flipped to WGBRIDGE (cgo). |
| | Gomobile-built `:wgbridge-aar` deleted. |
| | wireguard-go logs piped through `__android_log_write`. |
| | Android phone spot-check: both modes work, ChromeOS pings host. |
| **** | **This change** — `wireguard-android:tunnel` dep removed, + LEGACY_GOBACKEND code paths deleted. **APK 50.7 MB → 37.0 MB.** |

---

## 8. Rollback recipe — restoring wireguard-android

If a future bug in `libwgbridge_native.so` forces a fast revert,
here's the **complete** recipe. Reverse-chronological from

### 7.1 Dependency
1. In `gradle/libs.versions.toml`, restore:
 ```toml
 wg-tunnel = "1.0.20260102"
 wg-tunnel = { group = "com.wireguard.android", name = "tunnel", version.ref = "wg-tunnel" }
 ```
2. In `app/build.gradle.kts`, add back `implementation(libs.wg.tunnel)`.

### 7.2 Re-introduce the enums + selector
1. Recreate `data/HostingMode.kt` with `MODE_A` and `MODE_B` values
 (default to `MODE_A` — is still better; B is fallback).
2. Recreate `data/JoinerBackend.kt` with `WGBRIDGE` (default) and
 `LEGACY_GOBACKEND`.
3. Add the fields back to `SettingsStore.kt`:
 `hostingMode`, `joinerBackend`, their `StateFlow`s, and persist
 them under keys `hosting_mode` / `joiner_backend`. (The
 `resetToDefaults` scrub already references the legacy keys, so
 leftover prefs from a previous install will surface correctly.)

### 7.3 Re-add the legacy support classes
1. Recreate `WgrtcTunnel.kt`:
 ```kotlin
 import com.wireguard.android.backend.Tunnel
 class WgrtcTunnel(
 private val tunnelName: String,
 private val onState: (Tunnel.State) -> Unit,
 ) : Tunnel {
 override fun getName(): String = tunnelName
 override fun onStateChange(newState: Tunnel.State) = onState(newState)
 }
 ```
2. Recreate `data/RealTunnelEndpointController.kt` (controller that
 drives `GoBackend.setState(UP, DOWN)` for the candidate race).
 The git history of this file before is the source of truth.
3. In `WgrtcApp.kt`, restore the lazy `backend: GoBackend` val and
 the `import com.wireguard.android.backend.GoBackend` line.
4. Recreate `data/GoRuntimeGuard.kt` (in-process `AtomicBoolean`
 flags + `modeAUnsafe()` / `modeBUnsafe()` predicates). Call
 `GoRuntimeGuard.markModeBLoaded()` inside the new `backend`
 lazy initializer.

### 7.4 Re-introduce the legacy code paths in the view-model
This is the biggest piece. In `WgrtcViewModel.kt`:
1. Restore the `backendTunnel` field with its state-change
 listener (DOWN-clears `_activeTunnelId` etc.).
2. Restore the `init { ... hub.endpointUpdates.collect { ... } }`
 block's legacy branch that calls
 `WgrtcApp.instance.backend.setState(backendTunnel, UP,
 Config.parse(...))`.
3. Restore the `connect()` short-circuit (HOST_MODE +
 `hostingMode == MODE_B`).
4. Restore the joiner backend selector (the `if (joinerBackend ==
 WGBRIDGE) … else { RealTunnelEndpointController(...) }`).
5. Restore the hostname-Endpoint fallback (`Config.parse +
 setState(UP)` when candidates list is empty).
6. Restore `reconfigureHostTunnel`'s branch.
7. Restore the throughput sampler's GoBackend branch (reads from
 `WgrtcApp.instance.backend.getStatistics(backendTunnel)`).
8. Re-add the `latestHandshake(Statistics)` + `perPeerStats(Statistics)`
 helpers (used by the sampler).
9. Restore the `disconnect()` legacy `backend.setState(DOWN)` path.

The git diff that *introduced* is the canonical reverse-of-this
operation. Look for the commit titled something like " —
delete wireguard-android dependency".

### 7.5 Re-add UI
1. In `SettingsScreen.kt`, re-add the "Hosting mode" and "Joiner
 backend (advanced)" sections + `HostingModePicker` /
 `JoinerBackendPicker` composables.
2. In `HostModeSection.kt`, re-add the `ModeBadge` composable.

### 7.6 Optional: `DemoConfig.kt` + `WgSocketBinder.kt`
These were both dead code by the time hit. Reintroducing them
isn't necessary unless you specifically need:
- A hard-coded demo config to seed a fresh install (`DemoConfig`).
- The reflection harness for some future bind-the-WG-socket-
 to-a-Network experiment (`WgSocketBinder`).

### 7.7 What you do **not** need to do
- The cgo path (`wgbridge_native/`, `:wgbridge-native-aar`,
 `RealWgBridgeBackendNative`, `WgBridgeNative`, etc.) stays
 intact. The two runtimes are designed to coexist; this is exactly
 what the `GoRuntimeGuard` was protecting against. As long as a
 given process only loads one of them, both work.
- `WgQuickUapi.kt` stays in place — it's a self-contained parser.
- `JoinerVpnService.kt` stays in place. Its `start` + `reconfigure`
 methods are used by the WGBRIDGE path; LEGACY_GOBACKEND goes
 through `GoBackend$VpnService`, which the AAR registers in its
 own manifest.

### 7.8 Test that the rollback works
1. `./gradlew :app:testDebugUnitTest` should pass.
2. `./gradlew :app:assembleDebugAndroidTest` should pass.
3. Install on emulator. Set Settings → Hosting mode → . Set
 Settings → Joiner backend → LEGACY. Connect a tunnel. Verify
 the legacy path is exercised by reading `logcat -s wg-go`.

---

## 9. Swapping the WG backend

This is the *new* architecture's superpower. Because the boundary
is UAPI text, swapping wireguard-go for a different implementation
is a small surface change.

### 8.1 What "swap the backend" means

You want to ship the same app, with the same Kotlin code and the
same UI, but use one of:
- **amneziawg-go** — wireguard-go fork with obfuscation
 (`Jc`, `Jmin`, `Jmax`, ``, ``, ``–``).
- **wg-obfs** — another obfuscation fork.
- **mullvad's wireguard-go** — adds DAITA traffic shaping.
- **BoringTun** (Rust) — Cloudflare's userspace WG, exposed via a
 similar UAPI surface.

### 8.2 What changes

| Component | Change |
|---|---|
| `wgbridge_native/go.mod` | Replace `golang.zx2c4.com/wireguard` import with the new module path. |
| `wgbridge_native/api.go` | Most likely zero changes — the //export functions only touch `device.NewDevice`, `dev.IpcSet`, `dev.IpcGetOperation`. Almost every fork keeps that API. For BoringTun, this file gets rewritten as a `boringtun_ffi` wrapper, but the //export *signatures* stay the same. |
| `wgbridge_native/build.sh` | Possibly different `go mod` flags for replacement directives. |
| `wgbridge-native-aar/build.gradle.kts` | Possibly bump the version string in `nativeVersion()`. |
| Everything in `app/` | **Zero changes.** |

### 8.3 Why this is so much better than the old design

Before , swapping the WG backend would have meant:
1. Fork `wireguard-android` (because was bound to its
 classes).
2. Provide a `GoBackend` shim that implements the same Java surface
 but calls into the new library.
3. Make sure the Java/Tunnel/Config classes still match the
 wireguard-android shape.
4. Keep two parallel code paths (+ ) in sync
 semantically.

After , the entire Kotlin codebase is decoupled from
wireguard-go. The boundary is a text protocol every WG fork already
speaks. The amneziawg-go fork in particular has identical
`device.IpcSet` semantics — swapping it in is the literal minimum:
change one `import` line in `wgbridge_native/api.go`.

### 8.4 Caveats

UAPI is *de facto*-standardised, not formally so. Some forks add
*additional* UAPI keys (amneziawg adds `jc=`, `jmin=` etc. inside
the `[Interface]` device-scope). The Kotlin renderer (`WgQuickUapi`)
ignores wg-quick keys it doesn't understand — to use obfuscation
parameters you'd need to extend either the renderer (preferred) or
write the new device-scope lines into the UAPI text by some other
mechanism. The point is: **this is a Kotlin-side change in one
file**, not a multi-module surgery.

BoringTun is the trickier case: its Rust FFI doesn't use UAPI text;
it has a `wireguard_set_logging` / `wireguard_tunnel_new` /
`wireguard_write` / `wireguard_read` API. To swap in BoringTun
you'd implement the //export functions on top of BoringTun's FFI,
translating UAPI text → BoringTun's struct API. That's ~200 lines
of glue in `api.go`. The Kotlin side still doesn't change.

### 8.5 Recipe for adding amneziawg (a worked example)

1. `cd wgbridge_native && go mod edit -replace
 golang.zx2c4.com/wireguard=github.com/amnezia-vpn/amneziawg-go@latest
 && go mod tidy`
2. Rebuild: `./build.sh`
3. Extend `WgQuickUapi.kt` to accept `Jc`, `Jmin`, `Jmax`, ``,
 ``, ``–`` lines from the wg-quick text and emit them in
 the UAPI output. Add a corresponding `WgQuickUapiTest` case.
4. Run `HostNativeSelfLoopTest`. If it still completes a handshake
 in <5 ms, you're done; the obfuscation parameters are now
 plumbed through.

---

## 10. Files inventory (current state)

For anyone who needs to find a thing.

### Go side — `wgbridge_native/`

| File | Role |
|---|---|
| `go.mod` / `go.sum` | Vendored wireguard-go pin (`f333402bd9cb` as of writing). |
| `api.go` | The `//export` functions. Handle map + UAPI surface. |
| `jni_android.c` | JNI shims. One C function per Java method. |
| `logger_android.go` | wg-go → logcat via `__android_log_write`. |
| `logger_other.go` | Build-on-host fallback. |
| `build.sh` | NDK + cgo + Go build. Outputs `lib<abi>/libwgbridge_native.so`. |
| `the internal design doc` | archaeology — the decision tree we followed. |

### Kotlin side — `app/src/main/kotlin/com/gutschke/wgrtc/data/`

| File | Role |
|---|---|
| `WgBridgeNative.kt` | JNI surface (6 `external` functions). |
| `RealWgBridgeBackendNative.kt` | Kotlin wrapper that implements `WgBridgeBackend`. |
| `WgBridgeBackend.kt` | Interface for testability. |
| `WgQuickUapi.kt` | wg-quick text → UAPI text. |
| `UapiStatsParser.kt` | UAPI dump → `UapiStats`. |
| `ModeAHostBackend.kt` + `HostModeRunner.kt` | Host bridge lifecycle. |
| `JoinerWgRunner.kt` | Joiner bridge lifecycle (in process; service binding lives in `service/JoinerVpnService.kt`). |
| `WgBridgeTunnelEndpointController.kt` | Drives in-place endpoint updates during the candidate race. |

### androidTest — `app/src/androidTest/kotlin/com/gutschke/wgrtc/data/`

| Test | Validates |
|---|---|
| `HostNativeSelfLoopTest` | Host mode end-to-end with two bridges in one process. Slirp-NAT-immune. |
| `WgBridgeNativeHandshakeTest` | Joiner mode against a real kernel-WG peer in a sandbox netns. |
| `JoinerHandshakeInstrumentedTest` | High-level joiner connect path. |
| `ModeAHostBackendInstrumentedTest` | Lifecycle (start/stop/reconfigure) on real hardware. |
| `HostModeForwarderE2ETest` | Through-host TCP/UDP/ICMP to non-local destinations ( Option B). |

### Test orchestrators — `dev-env/`

| Script | Purpose |
|---|---|
| `sandbox-wg-server.sh` | Spawns a kernel-WG server in `unshare -Urn` netns + UDP socat bridge. |
| `sandbox-wg-client.sh` | Inverse — a kernel-WG client. |
| `wg-udp-bridge.py` | The UDP↔Unix-DGRAM bridge for the sandbox. |
| `run-c2-handshake-test.sh` | End-to-end joiner test orchestrator (emulator ↔ sandbox-wg-server). |

---

## 11. Open questions / things still on the roadmap

- listenTCP / listenUDP plumbing is now in (validated by
 `HostNativeListenerTest`). What's NOT wired yet:
 - `HostModeRunner` still passes `tcpPorts = emptyList()` /
 `udpPorts = emptyList()` everywhere. Wiring the listener
 surface to actual user-configurable port sets + forwarders
 is a follow-up.
 - The `TcpFlowForwarder` / `UdpFlowForwarder` classes exist
 from / but haven't been hooked into a listener
 invocation site yet.
- The legacy `wgbridge/` reference directory was deleted in .
 The rollback recipe in §7 is now the only place that
 reconstructs it.
- IPv6 listen sockets work at the wireguard-go layer (`conn.NewDefaultBind`
 binds both v4 and v6), but the gvisor netstack listener path
 (`tnet.ListenTCP`) is v4-only as we use it. v6 listening would
 need a separate `ListenTCPAddrPort(v6Addr)` codepath. Out of
 scope for now.
- We deliberately don't run wireguard-go inside R8 / ProGuard's
 view — the `.so` is opaque to the shrinker. No keep rules
 needed.
