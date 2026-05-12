#!/bin/bash
# build.sh — produce libwgbridge_native.so for arm64-v8a + x86_64
# via the NDK toolchain (no gomobile).
#
# Why this exists. The gomobile-built `wgbridge.aar` panics with
# `runtime.bulkBarrierPreWrite: unaligned arguments` when wireguard-go
# runs in TUN-fd mode (joiner) on the user's Android phone + on the x86_64
# emulator (only on first handshake — the spike skipped the trigger).
# wireguard-android pins the same wireguard-go commit and works
# because they build with cgo + //export instead of gomobile bind.
# This script replicates their approach for `wgbridge_native`.
#
# Pinned: Go 1.24.5 (wireguard-android uses 1.24.3; we match the
# minor-version family to dodge a possible Go 1.25 alignment
# regression — hypothesis H2).
#
# Output: $HERE/build/libwgbridge_native-<abi>.so for each ABI,
# packaged as `$HERE/build/jni/<abi>/libwgbridge_native.so` so the
# `wgbridge-native-aar` Gradle wrapper can drop them into an AAR.
#
# Run from anywhere; the script cd's into its own directory.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

# ──────────────────────────────────────────────────────────────────
# Anti-pattern lint. Bug-class checks for hazards we've burned
# debugging time on; cheaper than rediscovering each from a Pixel
# bugreport.
#
# Each entry: <regex pattern> <human-readable rule> <memory file>.
# A match anywhere in jni_android.c (excluding comment lines that
# start with `//`) fails the build with a pointer to the memory.
#
# To bypass for an audited exception, wrap the offending call in:
# /* LINT_OK <reason> */
# on the same line, but please update the memory doc first.
# ──────────────────────────────────────────────────────────────────
lint_jni() {
 local pattern="$1" rule="$2" memo="$3"
 local hits
 hits=$(grep -nE "^[[:space:]]*[^/[:space:]].*${pattern}" jni_android.c 2>/dev/null \
 | grep -v 'LINT_OK' || true)
 if [[ -n "$hits" ]]; then
 echo "[wgbridge_native] LINT FAILED: $rule" >&2
 echo " see memory: $memo" >&2
 echo "$hits" | sed 's/^/ /' >&2
 return 1
 fi
}

# N14h (2026-05-11): GetPrimitiveArrayCritical pins ART's GC
# ThreadFlip; any blocking call inside the region (gonet Read/Write,
# mutex, channel) deadlocks every subsequent critical region on
# every other thread — including Android framework internals
# (Parcel.writeByteArray, Socket() allocation), which ANR's the
# whole app. Use GetByteArrayRegion / SetByteArrayRegion (which
# copy and are safe across blocking) instead.
lint_jni 'GetPrimitiveArrayCritical|ReleasePrimitiveArrayCritical' \
 'GetPrimitiveArrayCritical is banned in this codebase (deadlocks ART under load)' \
 'feedback_jni_primitive_array_critical.md'


# Resolve toolchain. Prefer the project-local Go install if no
# system Go is present.
if ! command -v go >/dev/null 2>&1; then
 PROJECT_GO="$HERE/../../tmp/go-toolchain/go/bin"
 if [[ -x "$PROJECT_GO/go" ]]; then
 export PATH="$PROJECT_GO:$PATH"
 export GOROOT="$HERE/../../tmp/go-toolchain/go"
 else
 echo "[wgbridge_native] error: no 'go' on PATH" >&2
 exit 1
 fi
fi
export GOPATH="${GOPATH:-$HERE/../../tmp/go-toolchain/gopath}"
export GOCACHE="${GOCACHE:-$HERE/../../tmp/go-toolchain/gocache}"

# Pin to Go 1.24.5 — wireguard-android uses 1.24.3, we use the
# closest readily-available patch. Go 1.25.0 (which gomobile master
# requires) is the prime suspect for H2; building this spike under
# 1.24 is half the experiment.
export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.24.5}"

# NDK setup — same convention as wgbridge/build.sh.
export ANDROID_HOME="${ANDROID_HOME:-$HERE/../../tmp/android-sdk}"
NDK_DIR="$(ls -d "$ANDROID_HOME/ndk"/*/ 2>/dev/null | head -1 | sed 's:/$::')"
if [[ -z "$NDK_DIR" ]]; then
 echo "[wgbridge_native] error: no NDK found under $ANDROID_HOME/ndk/" >&2
 exit 1
fi
export ANDROID_NDK_HOME="$NDK_DIR"
HOST_TAG="$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)"
TOOLCHAIN_BIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG/bin"
if [[ ! -d "$TOOLCHAIN_BIN" ]]; then
 echo "[wgbridge_native] error: NDK toolchain not at $TOOLCHAIN_BIN" >&2
 exit 1
fi

API_LEVEL=26
mkdir -p build/jni

# Build for each ABI in sequence — fast enough that we don't bother
# parallelising; cgo cross-compile is mostly Go work + a clang link
# step at the end.
for ABI in arm64-v8a x86_64; do
 case "$ABI" in
 arm64-v8a)
 GOARCH=arm64
 CC_TARGET=aarch64-linux-android$API_LEVEL
 ;;
 x86_64)
 GOARCH=amd64
 CC_TARGET=x86_64-linux-android$API_LEVEL
 ;;
 esac

 echo "[wgbridge_native] building $ABI ($GOARCH, $CC_TARGET)"
 mkdir -p "build/jni/$ABI"
 OUT="build/jni/$ABI/libwgbridge_native.so"

 # Per-ABI clang from the NDK. CGO_CFLAGS / CGO_LDFLAGS lifted
 # from wireguard-android's Makefile — set --target so clang
 # generates Android-API-26 binaries; --build-id=none avoids
 # reproducibility skew across rebuilds.
 # WGRTC_DEBUG_BUILD=1 disables -trimpath + the -ldflags symbol
 # scrub so addr2line can resolve panic offsets back to Go
 # source lines. Production builds leave both enabled for
 # reproducibility. No -strip in either path; .so is loaded
 # by AGP which strips for release.
 if [[ -n "${WGRTC_DEBUG_BUILD:-}" ]]; then
 BUILD_LDFLAGS=""
 BUILD_TRIM=""
 echo "[wgbridge_native] (debug build — symbols retained)"
 else
 BUILD_LDFLAGS='-ldflags=-buildid='
 BUILD_TRIM="-trimpath"
 fi
 CC="$TOOLCHAIN_BIN/${CC_TARGET}-clang" \
 CXX="$TOOLCHAIN_BIN/${CC_TARGET}-clang++" \
 GOOS=android \
 GOARCH="$GOARCH" \
 CGO_ENABLED=1 \
 CGO_CFLAGS="--target=$CC_TARGET" \
 CGO_LDFLAGS="--target=$CC_TARGET -Wl,--build-id=none -Wl,-soname=libwgbridge_native.so" \
 go build \
 ${BUILD_LDFLAGS} \
 ${BUILD_TRIM} \
 -buildvcs=false \
 -buildmode=c-shared \
 -o "$OUT" \
 .

 if [[ ! -s "$OUT" ]]; then
 echo "[wgbridge_native] error: $OUT not produced" >&2
 exit 1
 fi
 size_kb=$(du -k "$OUT" | awk '{print $1}')
 echo "[wgbridge_native] $ABI: $OUT (~${size_kb} KB)"
done

echo "[wgbridge_native] done — libs under $HERE/build/jni/"
