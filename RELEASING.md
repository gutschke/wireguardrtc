# Releasing wgrtc

This repository ships two components on a unified version tag:

- the **daemon** (Linux, Debian package),
- the **Android app** (Google Play AAB).

A release tag advances both. We use semver: `vX.Y.Z`. Pre-release: `vX.Y.Z-alpha.N`.

## What gets bumped

- `daemon/wireguardrtc` — the `__version__` constant.
- `daemon/debian/changelog` — a new `wireguardrtc (X.Y.Z-1) UNRELEASED` entry; the Debian builder picks the version from here.
- `android/app/build.gradle.kts` — `versionName = "X.Y.Z"`; `versionCode` is a strictly increasing integer (independent of the semver tag).

Keep `versionCode` monotonic: the Play Console rejects uploads whose `versionCode` does not strictly exceed every previously-uploaded build, even those that were rolled back. Skipping numbers is allowed.

## Release checklist

```
1. Stabilise main.
   - `git status` clean, all CI green.
   - Decide the next semver from the changes since the previous tag.

2. Bump versions.
   - Update the daemon's `__version__`, the Debian changelog
     entry, and the Android `versionName` / `versionCode`.
   - Commit:  "Bump version to vX.Y.Z".

3. Build, sign, smoke-test.
   - Daemon:
       cd daemon && dpkg-buildpackage -us -uc -b
       sudo dpkg -i ../wireguardrtc_<X.Y.Z-1>_all.deb     # one-host smoke install
   - Android:
       cd android && ./gradlew :app:bundleRelease
       # produces app/build/outputs/bundle/release/app-release.aab
   - Sanity-check the daemon comes up cleanly + the AAB installs.

4. Tag and push.
       git tag -a vX.Y.Z -m "wgrtc vX.Y.Z"
       git push origin main --tags

5. Cut a GitHub Release for vX.Y.Z.
   - Attach the .deb to the release notes ("Daemon, signed by …").
   - Release notes: highlight user-visible changes, breaking
     changes (especially anything that touches the wire format
     between daemon and app), and any required config edits.

6. Push the Android AAB to the Play Console.
   - The Play upload key is in `android/app/keystore.properties`
     (gitignored). The key is currently held by Google via the
     Play App Signing program; the upload key signs the AAB
     locally and Play re-signs with the App Signing key.
   - Internal testing track today; promote to closed / open
     testing or production when ready.
   - Match the Play release name to the GitHub tag (`vX.Y.Z`).

7. Update the in-app About screen if the repo URL or license
   text changed.

8. Verify post-release.
   - Fresh install of the daemon from the .deb on a clean
     Debian/Ubuntu host.
   - Fresh install of the AAB on a Pixel device through Play's
     internal-testing channel.
```

## Hot-fix workflow

For a critical fix between scheduled releases:

1. Branch from the latest tag, cherry-pick the fix.
2. Bump the patch version (`vX.Y.Z` → `vX.Y.(Z+1)`).
3. Same checklist as above, condensed.

## Prebuilt APK for sideloading

Each release attaches a single **universal release APK** to the GitHub Release alongside the `.deb`. This is the path for users who can't (or don't want to) install through Play — typical reasons are: no Play Store on the device, no Google account, or wanting to track GitHub-attached binaries through tools like Obtainium.

The signing model is the recommended "option A" from the design discussion:

- **Signed with the Play upload key** (`android/app/keystore.properties`).  Once Google's Play App Signing kicks in, Play deliveries are re-signed with Google's app-signing key, so the GitHub-attached APK and the Play APK end up with **different signatures**.
- **Consequence**: a user who installs via sideload cannot in-place upgrade to the Play install or vice versa.  Android refuses cross-signature upgrades; the fix is uninstall + reinstall (which loses tunnel state).  Release notes call this out so users pick a channel and stick with it.
- This matches what Signal, Tailscale, and Mullvad do.

The build itself is straight `assembleRelease` — no per-ABI splits, no shrinking.  The resulting universal APK bundles the two ABIs `wgbridge_native` produces (`arm64-v8a` + `x86_64`) in a single file, so one binary covers phones, tablets, Chromebooks with developer mode, and the Android emulator.

### Build, sign, and attach

```bash
cd android

# Sanity-check that release signing is wired up (not the debug fallback).
# Look for "wgrtc-upload" in the v2 signing block.
./gradlew :app:assembleRelease
apksigner verify --print-certs \
    app/build/outputs/apk/release/app-release.apk | head -20

# Stage the artefact with a release-friendly filename.
mkdir -p ../dist
cp app/build/outputs/apk/release/app-release.apk \
   "../dist/wgrtc-vX.Y.Z.apk"
( cd ../dist && sha256sum "wgrtc-vX.Y.Z.apk" > "wgrtc-vX.Y.Z.apk.sha256" )
```

Smoke-test on at least one real device before tagging — install on top of any previous sideload install and verify the existing tunnel survives.  (If the release bumps the signing key it won't, and that's a release-notes-worthy event.)

Attach both `wgrtc-vX.Y.Z.apk` and `wgrtc-vX.Y.Z.apk.sha256` to the GitHub Release.  Standard filename pattern: `wgrtc-vX.Y.Z.apk` at the release root — stable enough for Obtainium-style auto-update tracking.

### Architectures and minimum platform

| Property | Value | Why |
|---|---|---|
| ABIs in the APK | `arm64-v8a`, `x86_64` | What `wgbridge_native/build.sh` produces. Covers ≈100% of in-warranty phones + ChromeOS + emulator. |
| `minSdk` | 26 (Android 8.0) | Matches what the codebase already requires; older Androids lack APIs we lean on. |
| `targetSdk` | 35 (Android 15) | Current Play floor; sets the runtime behaviour the app is tested against. |

`armeabi-v7a` is intentionally omitted: every phone shipped since 2019 is arm64, and dropping the 32-bit slice halves the JNI payload.  If a user reports a 32-bit-only device, build from source — `wgbridge_native/build.sh` will produce a v7a slice with `ABI_v7a=1`.

### What is **not** attached

- The `.aab` bundle.  That goes to Play Console, not the GitHub Release.
- The `debug` or `agent` build variants.  Both carry `applicationIdSuffix` and would install side-by-side with release, which is confusing in user reports.  They exist for development only.

Source-built APKs remain an option: instructions in [`android/README.md`](android/README.md#building).

## Tracking deferred / planned items

Roadmap items, design notes, and per-release scoping decisions belong in private project notes; this repository keeps only the released code + the docs that explain what shipped.
