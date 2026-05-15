// Package main is intentional — this Go package compiles to a
// `c-shared` library (`libwgbridge_native.so`) loaded into the
// Android app via `System.loadLibrary("wgbridge_native")`. It
// replaces the gomobile-bind-generated `wgbridge.aar` for the
// joiner-mode TUN-fd path that hits the
// `bulkBarrierPreWrite: unaligned arguments` panic on first
// handshake. See `the internal design doc`.
//
// Architecture follows wireguard-android's `tools/libwg-go`
// pattern verbatim:
//
// - This file declares `//export wgbridge*` functions with
// C-friendly signatures (Go strings via the `goString`
// layout, int handles, char* outputs).
// - `jni.c` (sibling) declares `Java_*` JNIEXPORT functions
// that adapt jstring↔Go-string and invoke the //exports.
// - `WgBridgeNative.kt` (in the app module) loads the .so,
// declares `external` native methods, exposes a Kotlin API.
//
// Handle-based state. We keep an int→bridgeState map so the
// JNI surface only exchanges handles (jints) with Java, never
// pointers. Pointers crossing the JNI boundary are exactly
// what gomobile gets wrong — the alignment check on writebarrier
// fires on a misaligned struct copy when an int handle would
// have been safer.
package main

import "C"

import (
	"fmt"
	"math"
	"net/netip"
	"os"
	"strings"
	"sync"
	"unsafe"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// makeWgLogger is provided by either the Android-only logger
// (logger_android.go, cgo + __android_log_write) or the fallback
// (logger_other.go, default device.NewLogger). The build tags
// pick the right one for the target.

// bridgeState owns one wireguard-go device + its associated TUN.
// Returned to Java as an int handle (key into [bridges]).
//
// `tnet` is non-nil only for host-mode bridges (gvisor netstack);
// joiner-mode bridges (TUN-fd) leave it nil. The split mirrors
// the original `wgbridge.Bridge` from the gomobile path so the
// Kotlin-side adapters (HostModeBackend etc.) can use either
// interchangeably.
type bridgeState struct {
	dev *device.Device
	tunDev tun.Device
	tnet *netstack.Net // host-mode only; nil in TUN-fd mode
	logger *device.Logger
}

var (
	bridgesMu sync.Mutex
	bridges = map[int32]*bridgeState{}
	nextID int32 // monotonic; never reused
)

// allocateHandle assigns a fresh int32 to [bs] and stores it in
// [bridges]. Returns the new handle.
func allocateHandle(bs *bridgeState) int32 {
	bridgesMu.Lock()
	defer bridgesMu.Unlock()
	for {
		nextID++
		if nextID == math.MaxInt32 {
			nextID = 1
		}
		if _, taken := bridges[nextID]; !taken {
			bridges[nextID] = bs
			return nextID
		}
	}
}

// lookupHandle returns the bridgeState for [handle], or nil.
func lookupHandle(handle int32) *bridgeState {
	bridgesMu.Lock()
	defer bridgesMu.Unlock()
	return bridges[handle]
}

// freeHandle removes [handle] from [bridges] and returns the
// bridgeState that was there (or nil if absent). Caller is
// responsible for shutting down the wireguard-go device.
func freeHandle(handle int32) *bridgeState {
	bridgesMu.Lock()
	defer bridgesMu.Unlock()
	bs, ok := bridges[handle]
	if !ok {
		return nil
	}
	delete(bridges, handle)
	return bs
}

// goStringToGo converts the (char*, n) pair the C wrappers pass
// us into a real Go string. We can't take a Go `string` directly
// as an //export argument because it's a managed type (the
// runtime would copy + GC it differently than C-side memory).
func goStringToGo(s *C.char, n C.long) string {
	if s == nil || n == 0 {
		return ""
	}
	return C.GoStringN(s, C.int(n))
}

// ─────────────────────────────────────────────────────────────────
// //export functions — JNI-callable via the wrappers in jni.c.

// wgbridgeVersion returns a build identifier the Stage-1 spike
// uses to confirm the cgo round-trip works. Now that we have the
// real surface, the version embeds the wireguard-go commit so
// later debugging knows which wg-go was linked in.
//
//export wgbridgeVersion
func wgbridgeVersion() *C.char {
	return C.CString("wgbridge_native v0.2 (wireguard-go " + wgGoVersion + ")")
}

const wgGoVersion = "f333402bd9cb"

// parseLocalAddrs splits a comma-separated address string into a
// slice of [netip.Addr] values, tolerating surrounding whitespace
// and empty entries (from trailing commas / accidental doubles).
// Bracketed v6 (`[fd00::1]`) is accepted since some callers pre-
// canonicalise that way before handing the string in.  Empty /
// whitespace-only input is an error.  A single bad entry rejects
// the whole list — partial application would silently drop
// addresses the operator typed.
//
// V6.H1: introduced for dual-stack host bridges; `10.99.0.1` and
// `10.99.0.1,fd00::1` both work.  Pure function — exhaustively
// unit-tested in parse_local_addrs_test.go.
func parseLocalAddrs(s string) ([]netip.Addr, error) {
	parts := strings.Split(s, ",")
	addrs := make([]netip.Addr, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Tolerate `[fd00::1]` form.
		if len(p) >= 2 && p[0] == '[' && p[len(p)-1] == ']' {
			p = p[1 : len(p)-1]
		}
		a, err := netip.ParseAddr(p)
		if err != nil {
			return nil, fmt.Errorf("invalid addr %q: %w", p, err)
		}
		addrs = append(addrs, a)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no valid addresses in %q", s)
	}
	return addrs, nil
}

// wgbridgeNew constructs a host-mode bridge with a userspace
// gvisor netstack. Used by (HOST_MODE tunnels).
//
// `localAddrStr` may be a single address or a comma-separated
// dual-stack list (V6.H1) — e.g. `10.99.0.1` or
// `10.99.0.1,fd00::1`.  `netstack.CreateNetTUN` already registers
// both v4 and v6 protocols and accepts a mixed-family slice; we
// just plumb the parsed list through.
//
// Returns:
//
//	> 0 : opaque handle
//	 -1 : invalid localAddr (parse failed)
//	 -2 : netstack.CreateNetTUN failed
//	 -3 : device.Up failed
//
// listenPort is wired through UAPI's "listen_port=N" line by the
// caller; pass 0 here to defer to UAPI. We accept it as a
// parameter for API symmetry with the gomobile Bridge but
// internally just discard it.
//
//export wgbridgeNew
func wgbridgeNew(localAddrStr *C.char, localAddrLen C.long, mtu C.int, listenPort C.int) C.int {
	localAddr := goStringToGo(localAddrStr, localAddrLen)
	addrs, err := parseLocalAddrs(localAddr)
	if err != nil {
		return -1
	}
	tunDev, tnet, err := netstack.CreateNetTUN(
		addrs,
		nil, // no DNS — caller drives sockets directly
		int(mtu),
	)
	if err != nil {
		return -2
	}
	logger := makeWgLogger()
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)
	if err := dev.Up(); err != nil {
		dev.Close()
		return -3
	}
	_ = listenPort // wired via UAPI ConfigureUAPI("listen_port=N")
	bs := &bridgeState{dev: dev, tunDev: tunDev, tnet: tnet, logger: logger}
	return C.int(allocateHandle(bs))
}

// wgbridgeSetFdProtector is retained for API symmetry with
// pre- builds: callers used to invoke it AFTER device open as
// a presence signal. The protect plumbing now goes through a
// process-global Java callback installed BEFORE the bridge opens
// (Kotlin's `WgBridgeNative.installProtector`), so this entry
// point has no work to do beyond validating the handle. Returns
// 0 on success, -1 on unknown handle.
//
//export wgbridgeSetFdProtector
func wgbridgeSetFdProtector(handle C.int) C.int {
	if lookupHandle(int32(handle)) == nil {
		return -1
	}
	return 0
}

// wgbridgeNewWithTunFd opens wireguard-go on an existing kernel TUN
// file descriptor (typically from Android's
// `VpnService.Builder.establish()`). Returns:
//
//	> 0 : opaque handle to be passed back to other functions
//	 -1 : invalid fd
//	 -2 : CreateUnmonitoredTUNFromFD failed
//	 -3 : device.Up failed
//
// The Bridge takes ownership of [fd] — closing the bridge closes
// the wrapped file (and therefore the fd).
//
//export wgbridgeNewWithTunFd
func wgbridgeNewWithTunFd(fd C.int) C.int {
	if fd < 0 {
		return -1
	}
	tunDev, _, err := tun.CreateUnmonitoredTUNFromFD(int(fd))
	if err != nil {
		// Best-effort fd close so we don't leak on the error path.
		_ = os.NewFile(uintptr(fd), "").Close()
		return -2
	}
	logger := makeWgLogger()
	// Joiner-mode wg-go runs inside a VpnService whose tun captures
	// the encrypted UDP we send back out — every outbound packet
	// would loop unless protect(fd) is called on the WG socket
	// before bind. newJoinerBind returns the protect-aware Bind on
	// Android; on host builds it falls back to StdNetBind.
	dev := device.NewDevice(tunDev, newJoinerBind(), logger)
	if err := dev.Up(); err != nil {
		dev.Close()
		return -3
	}
	bs := &bridgeState{dev: dev, tunDev: tunDev, logger: logger}
	return C.int(allocateHandle(bs))
}

// wgbridgeConfigureUAPI applies a UAPI string to the named bridge.
// Returns 0 on success or a negative errno-style code.
//
// -1 : invalid handle
// -2 : IpcSet failed (parse or peer-init error)
//
//export wgbridgeConfigureUAPI
func wgbridgeConfigureUAPI(handle C.int, uapiStr *C.char, uapiLen C.long) C.int {
	bs := lookupHandle(int32(handle))
	if bs == nil {
		return -1
	}
	uapi := goStringToGo(uapiStr, uapiLen)
	if err := bs.dev.IpcSet(uapi); err != nil {
		return -2
	}
	return 0
}

// wgbridgeSnapshotUAPI returns wireguard-go's current state as a
// UAPI dump (same format as wg(8)'s show ... dump). Returns NULL
// on error or invalid handle. C-side caller MUST free the
// returned char* (it was allocated via C.CString).
//
//export wgbridgeSnapshotUAPI
func wgbridgeSnapshotUAPI(handle C.int) *C.char {
	bs := lookupHandle(int32(handle))
	if bs == nil {
		return nil
	}
	var sb strings.Builder
	if err := bs.dev.IpcGetOperation(&sb); err != nil {
		return nil
	}
	return C.CString(sb.String())
}

// wgbridgeClose tears down the named bridge. Idempotent — calling
// twice with the same handle is a no-op the second time.
//
//export wgbridgeClose
func wgbridgeClose(handle C.int) {
	bs := freeHandle(int32(handle))
	if bs != nil {
		bs.dev.Close()
	}
}

// main exists because Go requires `package main` to have one,
// even when the binary is `c-shared` (no entrypoint). Empty body
// is fine — Go's linker doesn't emit it for `-buildmode=c-shared`.
func main() {}

// _ usage to silence unused-import warnings; both are referenced
// by exported functions but the Go compiler sometimes still
// warns until all paths exercise them.
var _ = unsafe.Sizeof(C.int(0))
var _ = fmt.Sprintf
