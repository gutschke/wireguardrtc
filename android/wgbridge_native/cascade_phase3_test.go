// Phase 3 tests for the host_forwarder ↔ cascade-ferry-registry
// integration introduced by CASCADE-2.  See plan §6 (route
// ownership, no SetRouteTable) and §7 (temp-local shadowing).

package main

import (
	"net/netip"
	"os"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	gvstack "gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Phase 3 §6 regression pin (source-lint): host_forwarder.go must
// not call SetRouteTable in production code.  SetRouteTable wipes
// the entire route table including any concurrent cascade routes,
// causing the leak the CASCADE-2 plan was specifically designed
// to prevent.
func TestHostForwarderNoSetRouteTable(t *testing.T) {
	raw, err := os.ReadFile("host_forwarder.go")
	if err != nil {
		t.Fatalf("read host_forwarder.go: %v", err)
	}
	// Strip Go line comments so a documentation reference to
	// SetRouteTable doesn't trigger the lint.
	src := stripGoLineCommentsForTest(string(raw))
	if strings.Contains(src, "SetRouteTable") {
		t.Fatalf("host_forwarder.go must not call SetRouteTable; " +
			"use AddRoute + RemoveRoutes(predicate) to preserve " +
			"concurrent cascade routes (CASCADE-2 §6)")
	}
}

// Phase 6 source-lint: cascade_ferry.go's drain loop must use
// InjectInbound (deliver to destination stack as if from the
// wire), not WritePackets (which queues for the source stack's
// Read — opposite direction).  The v2 review caught this as a
// MUST-FIX correctness bug.
func TestCascadeFerryUsesInjectInboundNotWritePackets(t *testing.T) {
	raw, err := os.ReadFile("cascade_ferry.go")
	if err != nil {
		t.Fatalf("read cascade_ferry.go: %v", err)
	}
	src := stripGoLineCommentsForTest(string(raw))
	if !strings.Contains(src, "InjectInbound") {
		t.Fatalf("cascade_ferry.go must call InjectInbound in its drain loop; " +
			"this is the load-bearing 'deliver to destination stack' primitive")
	}
	if strings.Contains(src, "WritePackets") {
		t.Fatalf("cascade_ferry.go must not use WritePackets in its drain loop — " +
			"that queues for the source stack's Read (wrong direction). " +
			"Use InjectInbound on the destination's channel.Endpoint")
	}
}

// Phase 3 §7 — ensureTempLocalAddress must skip registration when
// the destination falls under an active cascade prefix.  Without
// this skip, gvisor's HandleLocal=true on host-mode stacks would
// deliver the packet to the local stack and shadow the cascade
// route to the ferry NIC.
func TestEnsureTempLocalSkipsCascadeShadowedV4(t *testing.T) {
	// Set up a fresh registry with one cascade prefix and a host
	// bridge so HasCascadePrefix returns true for 10.50.0.5.
	r := newCascadeFerryRegistry()
	js := newJoinerStackForRegistry(t)
	defer js.Close()
	hs := newHostStack(t)
	defer hs.Close()
	r.RegisterJoinerStack(js, []netip.Prefix{netip.MustParsePrefix("10.50.0.0/24")})
	r.RegisterHostBridge(1, hs, []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")})
	restore := setCascadeFerryRegistryForTest(r)
	defer restore()
	// Verify our setup: HasCascadePrefix reports true.
	if !r.HasCascadePrefix(netip.MustParseAddr("10.50.0.5")) {
		t.Fatal("test setup wrong: 10.50.0.5 should be in cascade prefix")
	}

	// Construct a minimal hostForwarderState with a stack that
	// can accept AddProtocolAddress, so we can detect whether the
	// helper actually tried to register.
	stk := gvstack.New(gvstack.Options{
		NetworkProtocols: []gvstack.NetworkProtocolFactory{
			ipv4.NewProtocol, ipv6.NewProtocol,
		},
		HandleLocal: true,
	})
	defer stk.Close()
	ep := channel.New(64, 1500, "")
	const nicID tcpip.NICID = 1
	if err := stk.CreateNIC(nicID, ep); err != nil {
		t.Fatalf("CreateNIC: %s", err)
	}
	state := &hostForwarderState{
		stk:       stk,
		origNICID: nicID,
		tempAddrs: make(map[tcpip.Address]bool),
	}
	shadowed := tcpip.AddrFromSlice([]byte{10, 50, 0, 5})
	state.ensureTempLocalAddress(shadowed)
	if state.tempAddrs[shadowed] {
		t.Errorf("ensureTempLocalAddress should NOT have registered %v "+
			"(falls under active cascade prefix)", shadowed)
	}
	if state.tempAddrN.Load() != 0 {
		t.Errorf("tempAddrN counter should be 0; got %d", state.tempAddrN.Load())
	}
	// Sanity: an address NOT in the cascade prefix should
	// register normally.
	other := tcpip.AddrFromSlice([]byte{172, 16, 0, 5})
	state.ensureTempLocalAddress(other)
	if !state.tempAddrs[other] {
		t.Errorf("ensureTempLocalAddress should have registered %v "+
			"(not shadowed by any cascade prefix)", other)
	}
}

// Symmetric for v6.
func TestEnsureTempLocalSkipsCascadeShadowedV6(t *testing.T) {
	r := newCascadeFerryRegistry()
	js := newJoinerStackForRegistry(t)
	defer js.Close()
	hs := newHostStack(t)
	defer hs.Close()
	r.RegisterJoinerStack(js, []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")})
	r.RegisterHostBridge(1, hs, []netip.Prefix{netip.MustParsePrefix("fd00::/64")})
	restore := setCascadeFerryRegistryForTest(r)
	defer restore()

	stk := gvstack.New(gvstack.Options{
		NetworkProtocols: []gvstack.NetworkProtocolFactory{
			ipv4.NewProtocol, ipv6.NewProtocol,
		},
		HandleLocal: true,
	})
	defer stk.Close()
	ep := channel.New(64, 1500, "")
	const nicID tcpip.NICID = 1
	if err := stk.CreateNIC(nicID, ep); err != nil {
		t.Fatalf("CreateNIC: %s", err)
	}
	state := &hostForwarderState{
		stk:       stk,
		origNICID: nicID,
		tempAddrs: make(map[tcpip.Address]bool),
	}
	shadowed := tcpip.AddrFromSlice(netip.MustParseAddr("2001:db8::5").AsSlice())
	state.ensureTempLocalAddressV6(shadowed)
	if state.tempAddrs[shadowed] {
		t.Errorf("ensureTempLocalAddressV6 should NOT have registered %v "+
			"(cascade-shadowed)", shadowed)
	}

	other := tcpip.AddrFromSlice(netip.MustParseAddr("2606:4700::5").AsSlice())
	state.ensureTempLocalAddressV6(other)
	if !state.tempAddrs[other] {
		t.Errorf("ensureTempLocalAddressV6 should have registered %v "+
			"(unshadowed)", other)
	}
}

// ensureTempLocalAddress must not crash when the global registry
// is in its default empty state (no joiner stack registered).
// Production paths can call the forwarder before CascadeWiring
// has plumbed anything in.
func TestEnsureTempLocalNoRegistryNoSkip(t *testing.T) {
	r := newCascadeFerryRegistry()
	restore := setCascadeFerryRegistryForTest(r)
	defer restore()

	stk := gvstack.New(gvstack.Options{
		NetworkProtocols: []gvstack.NetworkProtocolFactory{
			ipv4.NewProtocol, ipv6.NewProtocol,
		},
		HandleLocal: true,
	})
	defer stk.Close()
	ep := channel.New(64, 1500, "")
	const nicID tcpip.NICID = 1
	if err := stk.CreateNIC(nicID, ep); err != nil {
		t.Fatalf("CreateNIC: %s", err)
	}
	state := &hostForwarderState{
		stk:       stk,
		origNICID: nicID,
		tempAddrs: make(map[tcpip.Address]bool),
	}
	addr := tcpip.AddrFromSlice([]byte{8, 8, 8, 8})
	state.ensureTempLocalAddress(addr)
	if !state.tempAddrs[addr] {
		t.Errorf("with empty registry, ensureTempLocalAddress should have registered %v", addr)
	}
}

// ----- helpers --------------------------------------------------

// stripGoLineCommentsForTest strips //... line comments from Go
// source.  Adequate for keyword-grep style source-lint tests.
func stripGoLineCommentsForTest(src string) string {
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
