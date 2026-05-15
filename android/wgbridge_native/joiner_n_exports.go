// JNI surface — `//export`-marked C-callable wrappers for
// the joiner-N shared-stack API. Each function adapts the
// internal Go types (`*sharedStackState`, `netip.Prefix`, ...) to
// the (handle, char*, length) shapes the JNI C wrappers in
// `jni_android.c` deal with.
//
// Error codes use the negative-int convention established by
// `wgbridgeNew` and friends — the Kotlin layer maps these to
// typed exceptions.

package main

import "C"

import (
	"net/netip"
	"strings"
)

// wgbridgeSharedStackNew creates a fresh shared netstack and
// returns its handle. Negative on error:
//
//	-1 : MTU out of range
//	-2 : newSharedStack failed (gvisor protocol-init error)
//
//export wgbridgeSharedStackNew
func wgbridgeSharedStackNew(mtu C.int) C.int {
	if mtu < 576 || mtu > 65535 {
		return -1
	}
	ss, err := newSharedStack(uint32(mtu))
	if err != nil {
		return -2
	}
	return C.int(allocateSharedStackHandle(ss))
}

// wgbridgeSharedStackClose tears down the stack identified by
// [handle]. Stops the kernel-TUN pump (if attached), closes all
// channel endpoints, and destroys the gvisor stack. Idempotent.
//
//export wgbridgeSharedStackClose
func wgbridgeSharedStackClose(handle C.int) {
	ss := freeSharedStack(int32(handle))
	if ss != nil {
		ss.close()
	}
}

// wgbridgeSharedStackAttachKernelTun wires fd as NIC 1 of [handle]
// and starts the read/write pump goroutines. Returns 0 on success;
// negative on error:
//
//	-1 : unknown stack handle
//	-2 : attachKernelTunPump failed (bad fd / duplicate / NIC create)
//
// The stack takes ownership of [fd]; closing the stack closes the
// fd. Caller MUST NOT close [fd] separately.
//
//export wgbridgeSharedStackAttachKernelTun
func wgbridgeSharedStackAttachKernelTun(handle C.int, fd C.int, mtu C.int) C.int {
	ss := lookupSharedStack(int32(handle))
	if ss == nil {
		return -1
	}
	if _, err := attachKernelTunPump(ss, int(fd), int(mtu)); err != nil {
		return -2
	}
	return 0
}

// wgbridgeSharedStackOpenJoiner allocates a new NIC on [stackHandle],
// opens a wireguard-go device on it, and programs routes for the
// joiner's AllowedIPs + interface addresses. Returns a bridge
// handle (positive) that the Kotlin layer feeds back into the
// existing `wgbridgeConfigureUAPI` / `wgbridgeSnapshotUAPI` /
// `wgbridgeClose` API. Closing the bridge automatically detaches
// the NIC from the shared stack.
//
// `peerAllowedCsv` is a comma-separated list of CIDRs (e.g.
// "10.99.0.0/24,fd00::/64") for forward (apps→this-joiner).
// `interfaceAddrsCsv` is the same shape for inbound
// (joiner→apps) — typically single /32 or /128 per family.
// Either list may be empty (a leading empty string), in which
// case that direction has no routes programmed.
//
// Return codes:
//
//	> 0 : bridge handle (success)
//	-1  : unknown stack handle
//	-2  : peer-allowed prefix parse failed
//	-3  : interface-addr prefix parse failed
//	-4  : openJoinerBridge failed (NIC create / wg-go Up / route program)
//
//export wgbridgeSharedStackOpenJoiner
func wgbridgeSharedStackOpenJoiner(
	stackHandle C.int,
	peerAllowedStr *C.char, peerAllowedLen C.long,
	interfaceAddrsStr *C.char, interfaceAddrsLen C.long,
	mtu C.int,
) C.int {
	ss := lookupSharedStack(int32(stackHandle))
	if ss == nil {
		return -1
	}
	peerAllowedRaw := goStringToGo(peerAllowedStr, peerAllowedLen)
	ifAddrsRaw := goStringToGo(interfaceAddrsStr, interfaceAddrsLen)

	peerAllowed, err := parsePrefixCsv(peerAllowedRaw)
	if err != nil {
		return -2
	}
	interfaceAddrs, err := parsePrefixCsv(ifAddrsRaw)
	if err != nil {
		return -3
	}
	bridgeHandle, _, err := openJoinerBridge(ss, peerAllowed, interfaceAddrs, int(mtu))
	if err != nil {
		return -4
	}
	return C.int(bridgeHandle)
}

// parsePrefixCsv splits a comma-separated CIDR list and parses
// each one with `netip.ParsePrefix`. Empty / all-whitespace
// input returns an empty slice (no routes) without error;
// individual entries are whitespace-trimmed to tolerate
// "10.0.0.0/24, fd00::/64" style input.
func parsePrefixCsv(s string) ([]netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	out := make([]netip.Prefix, 0, 4)
	for _, raw := range strings.Split(s, ",") {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, err
		}
		out = append(out, prefix)
	}
	return out, nil
}
