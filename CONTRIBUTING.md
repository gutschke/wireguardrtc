# Contributing to wgrtc

This repository hosts two components on a unified version tag — a Linux daemon and an Android app. Most changes touch just one of them; cross-component changes touch the [protocol design doc](docs/wg-holepunch-guide.md).

## Repository layout

```
.
├── daemon/                Linux daemon (Python 3 asyncio) + Debian packaging
│   ├── wireguardrtc           the daemon script
│   ├── wireguardrtc.conf      example global config
│   ├── peers.d.example/       example per-peer drop-ins
│   ├── wireguardrtc*.service  systemd units
│   ├── wireguardrtc.8         man page
│   ├── debian/                Debian source package
│   ├── tests/                 validation tests
│   └── ...
├── android/               Android client (Kotlin + cgo bridge to wireguard-go)
│   ├── app/                   the Android application
│   ├── signalling/            JVM-only protocol + crypto module
│   ├── wgbridge_native/       cgo + //export wrapper around wireguard-go + gvisor
│   ├── wgbridge-native-aar/   Gradle wrapper that packages the .so files
│   └── ...
├── docs/                  shared design + reference docs
│   ├── wg-holepunch-guide.md  authoritative protocol + crypto design
│   └── ...
├── THIRD_PARTY_LICENSES/  license texts for bundled / linked dependencies
├── LICENSE                Apache 2.0
├── NOTICE                 attribution summary
├── PRIVACY.md             user-facing privacy policy
├── README.md              orientation
└── RELEASING.md           release workflow
```

## Working on the daemon

See [`daemon/README.md`](daemon/README.md) for the runtime overview. Below is the developer flow.

### Prerequisites

Runtime (declared by the package, installed during `dpkg -i`): `python3`, `python3-venv`. The package's `postinst` creates `/var/lib/wireguardrtc/venv` and populates it from `requirements.txt`, which is why `dpkg -i` needs an internet connection.

For a from-source run:

```sh
cd daemon
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

Build-only:

```sh
# Debian / Ubuntu
sudo apt install debhelper devscripts fakeroot lintian
```

The package build itself requires no internet access — Python dependencies install at package-install time, not at build time.

### Day-to-day checks

```sh
cd daemon

# Syntax-check the daemon
python3 -m py_compile wireguardrtc && echo OK

# Render the man page (ASCII)
groff -t -man -Tascii wireguardrtc.8 | less

# Rebuild HTML / PDF design doc (writes into ../docs/)
source venv/bin/activate && ./build_docs.py
```

### Run from source

```sh
cd daemon
export WIREGUARDRTC_CONFIG_DIR=$HOME/wg-test
mkdir -p $HOME/wg-test/peers.d
cp wireguardrtc.conf $HOME/wg-test/
# Edit $HOME/wg-test/wireguardrtc.conf — set a real Salt value
sudo venv/bin/python3 ./wireguardrtc --log-level DEBUG
```

The installed binary uses the system venv shebang (`/var/lib/wireguardrtc/venv/bin/python3`), so from-source must use the local venv or an explicit interpreter.

To check the configuration without starting the daemon:

```sh
sudo wireguardrtc --show-config                              # installed binary
sudo venv/bin/python3 ./wireguardrtc --show-config           # from source
```

### Building the Debian package

```sh
cd daemon
chmod +x wireguardrtc       # must be executable or dpkg installs it 0644
dpkg-buildpackage -us -uc -b
```

Flags: `-b` binary-only, `-us`/`-uc` skip signing. The `.deb`, `.buildinfo`, and `.changes` files land in the **parent directory** (i.e. the repo root).

```sh
dpkg-deb --contents ../wireguardrtc_*.deb
dpkg-deb --info     ../wireguardrtc_*.deb
lintian --no-tag-display-limit ../wireguardrtc_*.deb        # expect: no-upstream-changelog
dpkg-buildpackage --target=clean                            # tidy
```

### Validation tests

See [`daemon/tests/README.md`](daemon/tests/README.md). Some need `sudo`.

```sh
cd daemon
./venv/bin/python tests/05_peerjs.py
```

### Protocol invariants — do not break

- `PROTOCOL_LABEL` in the daemon source is part of the on-wire format. Changing it silently breaks interoperability with every deployed instance.
- The PeerJS-compatible OFFER envelope shape (the WebRTC-flavoured wrapper around the encrypted blob) is also part of the wire format. The public broker silently disconnects clients whose first OFFER doesn't look like real WebRTC; the wrapper is the workaround. Self-hosted brokers accept anything, but we use one wire format everywhere.

## Working on the Android app

See [`android/README.md`](android/README.md) for the full developer setup. Quick summary:

```sh
cd android

# Build the cgo bridge once (per machine, per ABI):
( cd wgbridge_native && ./build.sh )

# Then the usual Gradle invocations:
./gradlew :app:assembleDebug                # debug APK
./gradlew :app:bundleRelease                # Play-store-ready AAB
./gradlew :app:testDebugUnitTest            # JVM unit tests
./gradlew :signalling:testDebugUnitTest
./gradlew :app:connectedDebugAndroidTest    # against a connected device / emulator
```

### Test layering

In rough order of which test type is fastest to get green:

1. **Pure-JVM unit tests** in `signalling/src/test/` and `app/src/test/`. No emulator needed. Run on every change to the protocol or to the app's data layer.
2. **Native-side Go tests** under `wgbridge_native/`. Reproduce most cgo-bridge bugs without going through Android at all.
3. **Instrumented tests** in `app/src/androidTest/`. Need a connected emulator or device with `adb`. Cover the JNI surface and the wgbridge ↔ kotlin handoff.
4. **Manual real-device validation**. Only when 1-3 pass.

Always start at the lowest layer that can reproduce a bug.

## Cross-component changes

Anything that changes the wire format between daemon and app:

1. Edit [`docs/wg-holepunch-guide.md`](docs/wg-holepunch-guide.md) first; treat the diff as the design review.
2. Implement the daemon side. Add a unit test using the daemon's `tests/05_peerjs.py` harness as a starting point.
3. Implement the Android side under `android/signalling/`. Add unit tests there.
4. Verify the new format is backward-compatible OR bump the protocol version field.

## Submitting changes

Pull requests welcome. Before opening one:

- Daemon changes:
  - `python3 -m py_compile daemon/wireguardrtc` is clean.
  - `groff -t -man -Tascii daemon/wireguardrtc.8 > /dev/null` is clean (man page still parses).
  - If the change is user-visible: a `dch -i` entry in `daemon/debian/changelog`.
  - `dpkg-buildpackage -us -uc -b` succeeds and `lintian` is clean (except the expected `no-upstream-changelog`).
- Android changes:
  - `./gradlew :app:testDebugUnitTest :signalling:testDebugUnitTest` passes.
  - If the change is user-visible: a note in the PR description for the release notes.
  - Version bumps land in the release commit, not in the feature commit (see [`RELEASING.md`](RELEASING.md)).

## License

Contributions are accepted under the [Apache License 2.0](LICENSE). By submitting a PR you certify that you have the right to license your contribution to this project under that license.
