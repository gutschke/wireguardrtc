// Tests for CASCADE-2 ferry registry.  TDD: tests written before
// the implementation in cascade_ferry_registry.go.
//
// The registry is the process-singleton lifecycle owner: tracks
// the active joiner-N shared stack + the active host bridges, and
// creates/destroys ferries when both are present / either gone.
// Also handles the joiner-N rebuild dance (drop-NIC route swap)
// per docs/cascade-2-plan.md §8.

package main

import (
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// newHostStack builds a minimal host-mode-style stack
// (HandleLocal=true) for registry tests.
func newHostStack(t *testing.T) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol, ipv6.NewProtocol,
		},
		HandleLocal: true,
	})
	if err := s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
		t.Fatalf("v4 forwarding: %s", err)
	}
	if err := s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true); err != nil {
		t.Fatalf("v6 forwarding: %s", err)
	}
	return s
}

// newJoinerStackForRegistry builds a joiner-N-style stack
// (HandleLocal=false) for registry tests.
func newJoinerStackForRegistry(t *testing.T) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol, ipv6.NewProtocol,
		},
		HandleLocal: false,
	})
	if err := s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
		t.Fatalf("v4 forwarding: %s", err)
	}
	if err := s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true); err != nil {
		t.Fatalf("v6 forwarding: %s", err)
	}
	return s
}

// 1. Joiner-N up alone: no ferries.
func TestRegistryJoinerStackAloneNoFerries(t *testing.T) {
	r := newCascadeFerryRegistry()
	js := newJoinerStackForRegistry(t)
	defer js.Close()

	r.RegisterJoinerStack(js, []netip.Prefix{netip.MustParsePrefix("10.50.0.0/24")})
	if got := r.activeFerryCount(); got != 0 {
		t.Fatalf("joiner alone should produce 0 ferries; got %d", got)
	}
}

// 2. Host bridge alone: no ferries.
func TestRegistryHostBridgeAloneNoFerries(t *testing.T) {
	r := newCascadeFerryRegistry()
	hs := newHostStack(t)
	defer hs.Close()

	r.RegisterHostBridge(1, hs, []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")})
	if got := r.activeFerryCount(); got != 0 {
		t.Fatalf("host alone should produce 0 ferries; got %d", got)
	}
}

// 3. Both present: one ferry per host bridge.
func TestRegistryBothPresentCreatesFerry(t *testing.T) {
	r := newCascadeFerryRegistry()
	js := newJoinerStackForRegistry(t)
	defer js.Close()
	hs := newHostStack(t)
	defer hs.Close()

	r.RegisterJoinerStack(js, []netip.Prefix{netip.MustParsePrefix("10.50.0.0/24")})
	r.RegisterHostBridge(1, hs, []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")})
	if got := r.activeFerryCount(); got != 1 {
		t.Fatalf("both present should produce 1 ferry; got %d", got)
	}
}

// 4. Unregister joiner stack → ferries stop, but host-side routes
//    on the host stack point at a drop-NIC (not removed entirely,
//    so traffic gets dropped during the rebuild gap).
func TestRegistryUnregisterJoinerSwapsToDropNic(t *testing.T) {
	r := newCascadeFerryRegistry()
	js := newJoinerStackForRegistry(t)
	defer js.Close()
	hs := newHostStack(t)
	defer hs.Close()

	r.RegisterJoinerStack(js, []netip.Prefix{netip.MustParsePrefix("10.50.0.0/24")})
	r.RegisterHostBridge(1, hs, []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")})

	// After both registered, host stack has cascade routes for
	// 10.50.0.0/24 (joiner's allowedIPs).
	if !hasRouteForPrefix(hs, netip.MustParsePrefix("10.50.0.0/24")) {
		t.Fatalf("expected cascade route 10.50.0.0/24 on host stack after both register")
	}

	r.UnregisterJoinerStack()
	if got := r.activeFerryCount(); got != 0 {
		t.Fatalf("after UnregisterJoinerStack, ferry count should be 0; got %d", got)
	}
	// The host-stack cascade route 10.50.0.0/24 should STILL be
	// present, pointing at a drop-NIC, so packets get dropped
	// during the rebuild gap instead of leaking via the
	// host_forwarder's catchall.
	if !hasRouteForPrefix(hs, netip.MustParsePrefix("10.50.0.0/24")) {
		t.Fatalf("expected drop-NIC cascade route 10.50.0.0/24 still on host stack after joiner gone")
	}
}

// 5. After both gone (joiner unreg, then host unreg), all
//    cascade routes are cleaned up from the host stack.
func TestRegistryFullTeardownClearsRoutes(t *testing.T) {
	r := newCascadeFerryRegistry()
	js := newJoinerStackForRegistry(t)
	defer js.Close()
	hs := newHostStack(t)
	defer hs.Close()

	r.RegisterJoinerStack(js, []netip.Prefix{netip.MustParsePrefix("10.50.0.0/24")})
	r.RegisterHostBridge(1, hs, []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")})
	r.UnregisterJoinerStack()
	r.UnregisterHostBridge(1)

	if hasRouteForPrefix(hs, netip.MustParsePrefix("10.50.0.0/24")) {
		t.Fatalf("after full teardown, cascade route should be gone")
	}
}

// 6. Multiple host bridges → one ferry each.
func TestRegistryMultipleHostBridges(t *testing.T) {
	r := newCascadeFerryRegistry()
	js := newJoinerStackForRegistry(t)
	defer js.Close()
	hs1 := newHostStack(t)
	defer hs1.Close()
	hs2 := newHostStack(t)
	defer hs2.Close()

	r.RegisterJoinerStack(js, []netip.Prefix{netip.MustParsePrefix("10.50.0.0/24")})
	r.RegisterHostBridge(1, hs1, []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")})
	r.RegisterHostBridge(2, hs2, []netip.Prefix{netip.MustParsePrefix("10.98.0.0/24")})
	if got := r.activeFerryCount(); got != 2 {
		t.Fatalf("two host bridges + joiner should yield 2 ferries; got %d", got)
	}
}

// 7. AllowedIPs change: cascade routes on host stack update.
func TestRegistryAllowedIPsChangeUpdatesHostRoutes(t *testing.T) {
	r := newCascadeFerryRegistry()
	js := newJoinerStackForRegistry(t)
	defer js.Close()
	hs := newHostStack(t)
	defer hs.Close()

	r.RegisterJoinerStack(js, []netip.Prefix{netip.MustParsePrefix("10.50.0.0/24")})
	r.RegisterHostBridge(1, hs, []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")})

	// Now joiner-N picks up another joiner with AllowedIPs covering
	// 192.168.5.0/24.
	r.OnJoinerAllowedIPsChanged([]netip.Prefix{
		netip.MustParsePrefix("10.50.0.0/24"),
		netip.MustParsePrefix("192.168.5.0/24"),
	})

	if !hasRouteForPrefix(hs, netip.MustParsePrefix("10.50.0.0/24")) {
		t.Fatalf("expected 10.50.0.0/24 still on host stack")
	}
	if !hasRouteForPrefix(hs, netip.MustParsePrefix("192.168.5.0/24")) {
		t.Fatalf("expected new 192.168.5.0/24 on host stack")
	}

	// Now joiner-N drops 10.50.0.0/24.
	r.OnJoinerAllowedIPsChanged([]netip.Prefix{
		netip.MustParsePrefix("192.168.5.0/24"),
	})
	if hasRouteForPrefix(hs, netip.MustParsePrefix("10.50.0.0/24")) {
		t.Fatalf("expected 10.50.0.0/24 removed from host stack after allowedIPs shrank")
	}
}

// 8. HasCascadePrefix lookup for the host_forwarder temp-local
//    consultation.
func TestRegistryHasCascadePrefix(t *testing.T) {
	r := newCascadeFerryRegistry()
	js := newJoinerStackForRegistry(t)
	defer js.Close()
	hs := newHostStack(t)
	defer hs.Close()

	r.RegisterJoinerStack(js, []netip.Prefix{netip.MustParsePrefix("10.50.0.0/24")})
	r.RegisterHostBridge(1, hs, []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")})

	if !r.HasCascadePrefix(netip.MustParseAddr("10.50.0.5")) {
		t.Errorf("10.50.0.5 should be in a cascade prefix")
	}
	if r.HasCascadePrefix(netip.MustParseAddr("172.16.0.5")) {
		t.Errorf("172.16.0.5 should NOT be in any cascade prefix")
	}
}

// ----- helpers --------------------------------------------------

// hasRouteForPrefix returns true if the stack's route table
// contains any route with destination matching [prefix] exactly.
func hasRouteForPrefix(s *stack.Stack, prefix netip.Prefix) bool {
	target, err := prefixToSubnet(prefix)
	if err != nil {
		return false
	}
	for _, r := range s.GetRouteTable() {
		if r.Destination.Equal(target) {
			return true
		}
	}
	return false
}

// Silence unused-warning during TDD.
var _ tcpip.NICID
