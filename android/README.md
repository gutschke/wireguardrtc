# wgrtc — Android app

The Android client for the wgrtc system — also installs on Chromebooks that support Android apps. Manages WireGuard tunnels, enrolls joiners through QR or 6-letter wormhole codes, and acts as a host for other peers when there is no Linux daemon available.

For an overview of how this fits into the larger system, see the [top-level README](../README.md).

## Highlights

- **Joiner mode.** Connect to any peer running the wgrtc daemon (or another wgrtc host). The app speaks the daemon's PeerJS-over-WSS signaling protocol, supports STUN-based endpoint roaming, and races multiple candidates in parallel to pick the lowest-latency path.
- **Host mode.** The phone itself can host a WireGuard tunnel that other peers join — useful when there is no fixed-IP server available. A built-in userspace network stack (`gvisor`) NATs traffic from joiners onto whatever upstream the phone happens to be using (Wi-Fi, cellular, or a tethered network).
- **Wormhole enrollment.** A 6-letter pronounceable code (PAKE-derived SAS) pairs two devices in seconds without QR codes or copy-paste of keys — handy when both devices are interactive but not co-located.
- **Foreground service.** Backgrounded long enough for the OS to start killing tasks, the OFFER listener stays alive via a `specialUse` foreground service so endpoint updates keep flowing.
- **Privacy.** No analytics, no cloud, no third-party sharing. Everything lives in the app's private storage; the only network traffic is the WireGuard tunnel itself plus end-to-end-encrypted signaling messages through whatever broker is configured (intended to be one you run yourself).
- **Dual-stack IPv6.** Joiners get a v4 + v6 address inside each tunnel; the through-host forwarder relays TCP, UDP, ICMP, and ICMPv6 traffic to both v4 and v6 destinations on the public internet. IPv6-only carriers (T-Mobile US) reach a dual-stack host directly without 464XLAT or a relay.

## Building

### Prerequisites

- Android SDK, API 35 (`compileSdk`), minimum API 26 (Android 8.0).
- JDK 17.
- A Linux or macOS host with `gcc` (or clang), Go 1.24.x (for the cgo bridge).
- Android NDK r25c or newer (for the cross-compilation toolchain).
- An emulator or physical device running Android 8+ (for `:app:assembleDebug`-based testing).

### One-time native build

The cgo wrapper around `wireguard-go` and `gvisor` (`libwgbridge_native.so`) is not checked into the repo. Produce it for both supported ABIs:

```sh
cd wgbridge_native
./build.sh
```

This writes `wgbridge_native/build/jni/<abi>/libwgbridge_native.so` for each ABI, where the Gradle `:wgbridge-native-aar` subproject picks them up. The script pins Go 1.24.5 and detects the NDK toolchain automatically from `ANDROID_NDK_HOME` or `local.properties`.

### Gradle

```sh
./gradlew :app:assembleDebug        # debug APK
./gradlew :app:bundleRelease         # signed AAB (kept for future use)
./gradlew :app:testDebugUnitTest     # JVM unit tests
./gradlew :signalling:testDebugUnitTest
./gradlew :app:connectedDebugAndroidTest   # instrumented tests against connected device/emulator
```

A `local.properties` pointing `sdk.dir` at your Android SDK is required (`./gradlew` will tell you if it can't find one).

## Repository layout

```
android/
├── app/                   the Android application (Compose UI, lifecycle, persistence)
├── signalling/            wormhole + broker + crypto module (pure-JVM testable)
├── wgbridge_native/       cgo + //export wrapper around wireguard-go + gvisor
├── wgbridge-native-aar/   Gradle wrapper that packages the .so files into an AAR
├── docs/                  Android-specific design notes
├── playstore-assets/      Icons, feature graphic, listing copy (kept on hand in case it's ever needed)
└── gradle/                Wrapper + version catalogue
```

The `app` module depends on `signalling` and `wgbridge-native-aar`. The `signalling` module is JVM-only on purpose so its protocol logic can be unit-tested without an emulator.

## Architecture notes

See `docs/wireguard-runtime-architecture.md` for why we link wireguard-go via cgo + `//export` (and not via `gomobile bind`), and `docs/ANDROID_NETWORKING_INVESTIGATIONS.md` for a war-story of Android's per-uid eBPF blocking and how we worked around it.

The `signalling/` module's protocol design is captured in the top-level [`docs/wg-holepunch-guide.md`](../docs/wg-holepunch-guide.md).

## Distribution

The app's package id is `com.gutschke.wgrtc`. It's distributed as a signed `.apk` on this repository's [Releases](../../releases) page; build it yourself with `./gradlew :app:assembleRelease` if you'd rather not trust a binary you didn't compile. [Obtainium](https://obtainium.imranr.dev/) can keep a sideloaded install up-to-date by polling Releases for new tags.

## License

[Apache License 2.0](../LICENSE).

Third-party components are listed in [`../NOTICE`](../NOTICE) and have their full license texts in [`../THIRD_PARTY_LICENSES/`](../THIRD_PARTY_LICENSES/).

WireGuard is a registered trademark of Jason A. Donenfeld.
