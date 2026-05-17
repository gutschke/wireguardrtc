// JNI surface for the CASCADE-2 ferry registry — the Kotlin
// CascadeWiring observer calls these as both backends'
// lifecycles fire.  Errors use the same negative-int convention
// as other wgbridge exports.
//
// Lifecycle: the registry singleton is created at package init
// (see cascade_ferry_registry.go).  Kotlin calls
// `RegisterJoinerStack` when joiner-N's shared stack comes up,
// `UnregisterJoinerStack` before it tears down (synchronously,
// to give us a chance to install drop-NIC routes before the
// stack disappears).  Likewise for host bridges.

package main

import "C"

import (
	"net/netip"
	"strings"
)

// wgbridgeSharedStackCascadeRegisterJoiner records the joiner-N
// shared stack identified by [stackHandle] in the cascade
// registry.  [allowedIpsCsv] is a comma-separated list of every
// active joiner's AllowedIPs prefixes (e.g.
// "10.50.0.0/24,2001:db8::/64").  Empty string is allowed and
// means "no cascade prefixes yet."
//
// Returns:
//	 0 : ok
//	-1 : unknown stack handle
//	-2 : malformed allowedIpsCsv
//
//export wgbridgeSharedStackCascadeRegisterJoiner
func wgbridgeSharedStackCascadeRegisterJoiner(
	stackHandle C.int,
	allowedIpsStr *C.char, allowedIpsLen C.long,
) C.int {
	ss := lookupSharedStack(int32(stackHandle))
	if ss == nil {
		return -1
	}
	raw := goStringToGo(allowedIpsStr, allowedIpsLen)
	prefixes, err := parsePrefixCsv(raw)
	if err != nil {
		return -2
	}
	getCascadeFerryRegistry().RegisterJoinerStack(ss.stack, prefixes)
	return 0
}

// wgbridgeSharedStackCascadeUnregisterJoiner removes the joiner
// stack from the registry.  MUST be called BEFORE the joiner
// stack itself is destroyed, so the registry has a chance to
// install drop-NIC routes (otherwise cascade traffic on the
// host stack would leak through the host_forwarder's catchall
// during the rebuild gap).
//
//export wgbridgeSharedStackCascadeUnregisterJoiner
func wgbridgeSharedStackCascadeUnregisterJoiner() {
	getCascadeFerryRegistry().UnregisterJoinerStack()
}

// wgbridgeSharedStackCascadeOnAllowedIPsChanged updates the
// joiner-N AllowedIPs union when joiners come or go without a
// full stack rebuild.  Idempotent.
//
//export wgbridgeSharedStackCascadeOnAllowedIPsChanged
func wgbridgeSharedStackCascadeOnAllowedIPsChanged(
	allowedIpsStr *C.char, allowedIpsLen C.long,
) C.int {
	raw := goStringToGo(allowedIpsStr, allowedIpsLen)
	prefixes, err := parsePrefixCsv(raw)
	if err != nil {
		return -1
	}
	getCascadeFerryRegistry().OnJoinerAllowedIPsChanged(prefixes)
	return 0
}

// wgbridgeSharedStackCascadeRegisterHostBridge records the
// host-mode bridge identified by [bridgeHandle] in the cascade
// registry.  [peerSubnetsCsv] is a comma-separated list of the
// host bridge's claimed subnets (typically the host's WG-side
// /24 + /64 in dual-stack mode).
//
// Returns:
//	 0 : ok
//	-1 : unknown bridge handle
//	-2 : malformed peerSubnetsCsv
//	-3 : bridge has no tnet (i.e. it's a TUN-fd-mode joiner,
//	     not a host-mode bridge — cascade doesn't apply)
//
//export wgbridgeSharedStackCascadeRegisterHostBridge
func wgbridgeSharedStackCascadeRegisterHostBridge(
	bridgeHandle C.int,
	peerSubnetsStr *C.char, peerSubnetsLen C.long,
) C.int {
	bs := lookupHandle(int32(bridgeHandle))
	if bs == nil {
		return -1
	}
	if bs.tnet == nil {
		return -3
	}
	raw := goStringToGo(peerSubnetsStr, peerSubnetsLen)
	prefixes, err := parsePrefixCsv(raw)
	if err != nil {
		return -2
	}
	stk := extractStack(bs.tnet)
	if stk == nil {
		return -3
	}
	getCascadeFerryRegistry().RegisterHostBridge(int32(bridgeHandle), stk, prefixes)
	return 0
}

// wgbridgeSharedStackCascadeUnregisterHostBridge removes a host
// bridge from the registry.  Called before the host bridge is
// closed.
//
//export wgbridgeSharedStackCascadeUnregisterHostBridge
func wgbridgeSharedStackCascadeUnregisterHostBridge(bridgeHandle C.int) {
	getCascadeFerryRegistry().UnregisterHostBridge(int32(bridgeHandle))
}

// wgbridgeSharedStackCascadeHasPrefix returns 1 if [addr] (a
// literal IPv4 or IPv6 string) falls under any active cascade
// prefix, 0 otherwise.  Exported for diagnostics — the Go-side
// host_forwarder already consults the registry directly.
//
//export wgbridgeSharedStackCascadeHasPrefix
func wgbridgeSharedStackCascadeHasPrefix(
	addrStr *C.char, addrLen C.long,
) C.int {
	raw := strings.TrimSpace(goStringToGo(addrStr, addrLen))
	if raw == "" {
		return 0
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return 0
	}
	if getCascadeFerryRegistry().HasCascadePrefix(addr) {
		return 1
	}
	return 0
}
