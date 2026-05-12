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

## Prebuilt APKs

We do **not** currently attach prebuilt APKs to GitHub Releases. The trade-off is that a GitHub-attached APK and the Play-distributed APK sign with different keys and therefore cannot upgrade each other — the user has to uninstall one to install the other, losing their tunnel state.

If we eventually want to ship a GitHub APK channel:

- It must be signed by a **separate, dedicated upload key** that is not the Play upload key — confusing the two would lock us out of future Play uploads if the Play key is lost.
- The release notes must clearly state "use this APK only if you cannot access the Play internal testing track; you will not get over-the-air updates from this channel".

Source-built APKs are always available: instructions in [`android/README.md`](android/README.md#building).

## Tracking deferred / planned items

Roadmap items, design notes, and per-release scoping decisions belong in private project notes; this repository keeps only the released code + the docs that explain what shipped.
