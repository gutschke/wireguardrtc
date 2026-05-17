// Tests for the CASCADE-2 cross-stack ferry.  TDD: these tests
// were written before the implementation in cascade_ferry.go.
//
// The ferry is a paired channel.Endpoint bridge between a
// host-mode gvisor stack (HandleLocal=true) and the joiner-N
// shared gvisor stack (HandleLocal=false).  Each direction has a
// drain-loop goroutine that reads packets off one endpoint and
// delivers them inbound on the other via `InjectInbound`.
//
// See docs/cascade-2-plan.md §1-4 for the design.

package main

import (
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// twoStackRig builds two minimal gvisor stacks suitable for ferry
// tests: one with `HandleLocal: true` (mimicking host-mode's
// netstack.CreateNetTUN behaviour), one with `HandleLocal: false`
// (mimicking joiner-N's newSharedStack).
//
// Each stack also gets a "source" NIC where the test injects
// packets — this is the NIC that gvisor's IP layer treats as the
// inbound interface for the test packet.  Cascade routes installed
// on each stack point at the ferry's NIC on that stack; LPM picks
// the ferry route for packets matching the cascade prefix.
type twoStackRig struct {
	hostStack    *stack.Stack
	joinerStack  *stack.Stack
	hostSrcEp    *channel.Endpoint  // packet-injection NIC, host side
	joinerSrcEp  *channel.Endpoint  // packet-injection NIC, joiner side
	hostSrcNIC   tcpip.NICID
	joinerSrcNIC tcpip.NICID
}

func newTwoStackRig(t *testing.T, mtu uint32) *twoStackRig {
	t.Helper()

	host := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol, ipv6.NewProtocol,
		},
		HandleLocal: true, // matches netstack.CreateNetTUN
	})
	joiner := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol, ipv6.NewProtocol,
		},
		HandleLocal: false, // matches newSharedStack
	})

	// Enable forwarding so injected packets can be routed across NICs.
	if err := host.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
		t.Fatalf("host SetForwardingDefaultAndAllNICs v4: %s", err)
	}
	if err := host.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true); err != nil {
		t.Fatalf("host SetForwardingDefaultAndAllNICs v6: %s", err)
	}
	if err := joiner.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
		t.Fatalf("joiner SetForwardingDefaultAndAllNICs v4: %s", err)
	}
	if err := joiner.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true); err != nil {
		t.Fatalf("joiner SetForwardingDefaultAndAllNICs v6: %s", err)
	}

	hostSrcEp := channel.New(64, mtu, "")
	joinerSrcEp := channel.New(64, mtu, "")
	const hostSrcNIC tcpip.NICID = 100
	const joinerSrcNIC tcpip.NICID = 100
	if err := host.CreateNIC(hostSrcNIC, hostSrcEp); err != nil {
		t.Fatalf("host CreateNIC: %s", err)
	}
	if err := joiner.CreateNIC(joinerSrcNIC, joinerSrcEp); err != nil {
		t.Fatalf("joiner CreateNIC: %s", err)
	}

	// Joiner-stack NICs need strong-host markers because
	// HandleLocal=false enforces them at FindRoute time.
	if err := bindStrongHostMarkers(joiner, joinerSrcNIC); err != nil {
		t.Fatalf("bindStrongHostMarkers joinerSrc: %s", err)
	}
	// Even though host stack is HandleLocal=true, the source NIC
	// where we inject test packets needs at least one address for
	// gvisor's IP layer to consider it a valid ingress for
	// forwarding decisions.  Add markers here too — production
	// host-mode's "source NIC" is wg-go's tun.Device which has
	// the host's WG-side address bound.
	if err := bindStrongHostMarkers(host, hostSrcNIC); err != nil {
		t.Fatalf("bindStrongHostMarkers hostSrc: %s", err)
	}
	return &twoStackRig{
		hostStack:    host,
		joinerStack:  joiner,
		hostSrcEp:    hostSrcEp,
		joinerSrcEp:  joinerSrcEp,
		hostSrcNIC:   hostSrcNIC,
		joinerSrcNIC: joinerSrcNIC,
	}
}

func (r *twoStackRig) close() {
	r.hostStack.Close()
	r.joinerStack.Close()
}

// injectV4At pushes [raw] (an IPv4 packet) at [nicID] on [s] as
// if it had just arrived from that NIC's link layer.
func injectV4Helper(s *stack.Stack, nicID tcpip.NICID, raw []byte) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(raw),
	})
	defer pkt.DecRef()
	// We need the channel endpoint to deliver, but we don't have a
	// direct reference here — InjectInbound is on the channel.Endpoint
	// itself, not the stack.  Tests use rig.hostSrcEp.InjectInbound
	// or rig.joinerSrcEp.InjectInbound directly.
	_ = pkt
	_ = s
	_ = nicID
}

// craftIPv4UDP / craftIPv6UDP — reuse from joiner_n_router_spike_test.go.
// We don't redefine them here; they're in the same package.

// 1. Host-to-joiner: packet matching a host-stack cascade route
//    emerges on the joiner-stack ferry NIC, deliverable to a
//    listener on a joiner-stack NIC (via gvisor routing inside
//    the joiner stack).
func TestCascadeFerryHostToJoinerDirection(t *testing.T) {
	rig := newTwoStackRig(t, 1500)
	defer rig.close()

	ferry, err := newCascadeFerry(rig.hostStack, rig.joinerStack, 1500)
	if err != nil {
		t.Fatalf("newCascadeFerry: %s", err)
	}
	defer ferry.Stop()

	// Cascade route on host stack: 10.50.0.0/24 → ferry's host NIC.
	cascadePrefix := netip.MustParsePrefix("10.50.0.0/24")
	if err := ferry.AddHostRoute(cascadePrefix); err != nil {
		t.Fatalf("AddHostRoute: %s", err)
	}

	// Sink NIC on joiner stack that catches anything reaching
	// 10.50.0.5.  We make it a /32 route pointing at a dedicated
	// channel endpoint so we can Read packets out of it.
	sinkEp := channel.New(64, 1500, "")
	const sinkNIC tcpip.NICID = 200
	if err := rig.joinerStack.CreateNIC(sinkNIC, sinkEp); err != nil {
		t.Fatalf("create joiner sink NIC: %s", err)
	}
	if err := bindStrongHostMarkers(rig.joinerStack, sinkNIC); err != nil {
		t.Fatalf("markers on sink NIC: %s", err)
	}
	rig.joinerStack.AddRoute(tcpip.Route{
		Destination: mustSubnet(netip.MustParsePrefix("10.50.0.0/24")),
		NIC:         sinkNIC,
	})

	// Inject packet at host stack's source NIC, dst=10.50.0.5.
	src := netip.MustParseAddr("192.0.2.1")
	dst := netip.MustParseAddr("10.50.0.5")
	raw := craftIPv4UDP(src, dst, 1234, 53, []byte("cascade-hello"))

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(raw),
	})
	rig.hostSrcEp.InjectInbound(header.IPv4ProtocolNumber, pkt)
	pkt.DecRef()

	// Wait briefly for the cascade to deliver.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got := sinkEp.Read(); got != nil {
			defer got.DecRef()
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("packet never arrived on joiner-stack sink NIC; cascade ferry did not forward")
}

// 2. Joiner-to-host: reverse direction.
func TestCascadeFerryJoinerToHostDirection(t *testing.T) {
	rig := newTwoStackRig(t, 1500)
	defer rig.close()

	ferry, err := newCascadeFerry(rig.hostStack, rig.joinerStack, 1500)
	if err != nil {
		t.Fatalf("newCascadeFerry: %s", err)
	}
	defer ferry.Stop()

	cascadePrefix := netip.MustParsePrefix("10.99.0.0/24")
	if err := ferry.AddJoinerRoute(cascadePrefix); err != nil {
		t.Fatalf("AddJoinerRoute: %s", err)
	}

	// Sink NIC on host stack.  Even though host stack is
	// HandleLocal=true, we bind markers here so the NIC has an
	// address and gvisor's forwarding path can construct an
	// egress route (FindRoute scans NICs for a usable
	// source-address candidate even when forwarding).
	sinkEp := channel.New(64, 1500, "")
	const sinkNIC tcpip.NICID = 200
	if err := rig.hostStack.CreateNIC(sinkNIC, sinkEp); err != nil {
		t.Fatalf("create host sink NIC: %s", err)
	}
	if err := bindStrongHostMarkers(rig.hostStack, sinkNIC); err != nil {
		t.Fatalf("markers on host sink NIC: %s", err)
	}
	rig.hostStack.AddRoute(tcpip.Route{
		Destination: mustSubnet(netip.MustParsePrefix("10.99.0.0/24")),
		NIC:         sinkNIC,
	})

	src := netip.MustParseAddr("10.50.0.1")
	dst := netip.MustParseAddr("10.99.0.5")
	raw := craftIPv4UDP(src, dst, 1234, 53, []byte("reverse-cascade"))

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(raw),
	})
	rig.joinerSrcEp.InjectInbound(header.IPv4ProtocolNumber, pkt)
	pkt.DecRef()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got := sinkEp.Read(); got != nil {
			defer got.DecRef()
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("packet never arrived on host-stack sink NIC; reverse cascade did not forward")
}

// 3. IPv6 in both directions.
func TestCascadeFerryV6Direction(t *testing.T) {
	rig := newTwoStackRig(t, 1500)
	defer rig.close()

	ferry, err := newCascadeFerry(rig.hostStack, rig.joinerStack, 1500)
	if err != nil {
		t.Fatalf("newCascadeFerry: %s", err)
	}
	defer ferry.Stop()

	cascadePrefix := netip.MustParsePrefix("2001:db8::/64")
	if err := ferry.AddHostRoute(cascadePrefix); err != nil {
		t.Fatalf("AddHostRoute v6: %s", err)
	}

	sinkEp := channel.New(64, 1500, "")
	const sinkNIC tcpip.NICID = 200
	if err := rig.joinerStack.CreateNIC(sinkNIC, sinkEp); err != nil {
		t.Fatalf("create joiner sink NIC: %s", err)
	}
	if err := bindStrongHostMarkers(rig.joinerStack, sinkNIC); err != nil {
		t.Fatalf("markers on sink NIC: %s", err)
	}
	rig.joinerStack.AddRoute(tcpip.Route{
		Destination: mustSubnet(netip.MustParsePrefix("2001:db8::/64")),
		NIC:         sinkNIC,
	})

	src := netip.MustParseAddr("fd00::1")
	dst := netip.MustParseAddr("2001:db8::5")
	raw := craftIPv6UDP(src, dst, 1234, 53, []byte("v6-cascade"))

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(raw),
	})
	rig.hostSrcEp.InjectInbound(header.IPv6ProtocolNumber, pkt)
	pkt.DecRef()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got := sinkEp.Read(); got != nil {
			defer got.DecRef()
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("v6 packet never arrived on joiner-stack sink NIC")
}

// 4. Stop releases drain-loop goroutines.
func TestCascadeFerryStopReleasesGoroutines(t *testing.T) {
	rig := newTwoStackRig(t, 1500)
	defer rig.close()

	before := runtime.NumGoroutine()

	ferry, err := newCascadeFerry(rig.hostStack, rig.joinerStack, 1500)
	if err != nil {
		t.Fatalf("newCascadeFerry: %s", err)
	}

	// Ferry should add 2 drain-loop goroutines.  Allow time for
	// them to be scheduled and noticed.
	time.Sleep(20 * time.Millisecond)
	during := runtime.NumGoroutine()
	if during <= before {
		t.Fatalf("ferry didn't appear to start drain-loop goroutines: before=%d during=%d",
			before, during)
	}

	ferry.Stop()

	// Wait for goroutines to exit.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("after Stop, goroutine count never dropped to baseline: "+
		"before=%d after=%d", before, runtime.NumGoroutine())
}

// 5. Stop drains in-flight packets (or explicitly discards them
//    via the cancel path).  We don't assert *delivery* on shutdown
//    since the spec allows graceful drop on close, but we do
//    assert Stop doesn't hang and no panic.
func TestCascadeFerryStopDrainsInFlight(t *testing.T) {
	rig := newTwoStackRig(t, 1500)
	defer rig.close()

	ferry, err := newCascadeFerry(rig.hostStack, rig.joinerStack, 1500)
	if err != nil {
		t.Fatalf("newCascadeFerry: %s", err)
	}

	// Saturate the host-side endpoint with packets, then
	// immediately Stop.  No panic, no hang.
	for i := 0; i < 10; i++ {
		src := netip.MustParseAddr("192.0.2.1")
		dst := netip.MustParseAddr("10.50.0.5")
		raw := craftIPv4UDP(src, dst, 1234, 53, []byte("inflight"))
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(raw),
		})
		rig.hostSrcEp.InjectInbound(header.IPv4ProtocolNumber, pkt)
		pkt.DecRef()
	}

	doneCh := make(chan struct{})
	go func() {
		ferry.Stop()
		close(doneCh)
	}()

	select {
	case <-doneCh:
		// OK.
	case <-time.After(2 * time.Second):
		t.Fatalf("Stop() hung")
	}
}

// 6. AddHostRoute / RemoveHostRoute leaves the host stack route
//    table empty after pair.
func TestCascadeFerryRouteAddRemove(t *testing.T) {
	rig := newTwoStackRig(t, 1500)
	defer rig.close()

	ferry, err := newCascadeFerry(rig.hostStack, rig.joinerStack, 1500)
	if err != nil {
		t.Fatalf("newCascadeFerry: %s", err)
	}
	defer ferry.Stop()

	prefix := netip.MustParsePrefix("10.50.0.0/24")
	before := len(rig.hostStack.GetRouteTable())
	if err := ferry.AddHostRoute(prefix); err != nil {
		t.Fatalf("AddHostRoute: %s", err)
	}
	if got := len(rig.hostStack.GetRouteTable()); got != before+1 {
		t.Fatalf("host stack route table size after AddHostRoute: got=%d want=%d",
			got, before+1)
	}
	if err := ferry.RemoveHostRoute(prefix); err != nil {
		t.Fatalf("RemoveHostRoute: %s", err)
	}
	if got := len(rig.hostStack.GetRouteTable()); got != before {
		t.Fatalf("host stack route table size after RemoveHostRoute: got=%d want=%d",
			got, before)
	}
}

// 7. Strong-host markers: joiner-side ferry NIC has v4 + v6
//    markers; host-side ferry NIC has NONE (HandleLocal=true on
//    host stack means markers aren't required and binding them
//    would add noise to the address table).
func TestCascadeFerryStrongHostMarkers(t *testing.T) {
	rig := newTwoStackRig(t, 1500)
	defer rig.close()

	ferry, err := newCascadeFerry(rig.hostStack, rig.joinerStack, 1500)
	if err != nil {
		t.Fatalf("newCascadeFerry: %s", err)
	}
	defer ferry.Stop()

	// Joiner-side ferry NIC must have v4 + v6 markers.
	v4Marker := nicMarker(ferry.joinerNicID)
	v6Marker := nicMarkerV6(ferry.joinerNicID)
	joinerAddrs := rig.joinerStack.AllAddresses()[ferry.joinerNicID]
	hasV4, hasV6 := false, false
	for _, a := range joinerAddrs {
		addr := a.AddressWithPrefix.Address
		switch addr.Len() {
		case 4:
			if addr.As4() == v4Marker.As4() {
				hasV4 = true
			}
		case 16:
			if got, ok := tcpipAddressToNetip(addr); ok && got == v6Marker {
				hasV6 = true
			}
		}
	}
	if !hasV4 {
		t.Errorf("joiner ferry NIC missing v4 marker %v; addrs=%v",
			v4Marker, joinerAddrs)
	}
	if !hasV6 {
		t.Errorf("joiner ferry NIC missing v6 marker %v; addrs=%v",
			v6Marker, joinerAddrs)
	}

	// Host-side ferry NIC: empirically gvisor's v6 forwarding
	// requires the egress NIC to have a v6 address of some kind
	// (even though HandleLocal=true is supposed to be permissive
	// about local-delivery checks).  We bind strong-host markers
	// on both sides so v6 forwarding works across the cascade
	// boundary in both directions.
	hostV4Marker := nicMarker(ferry.hostNicID)
	hostV6Marker := nicMarkerV6(ferry.hostNicID)
	hostAddrs := rig.hostStack.AllAddresses()[ferry.hostNicID]
	hostHasV4, hostHasV6 := false, false
	for _, a := range hostAddrs {
		addr := a.AddressWithPrefix.Address
		switch addr.Len() {
		case 4:
			if addr.As4() == hostV4Marker.As4() {
				hostHasV4 = true
			}
		case 16:
			if got, ok := tcpipAddressToNetip(addr); ok && got == hostV6Marker {
				hostHasV6 = true
			}
		}
	}
	if !hostHasV4 {
		t.Errorf("host ferry NIC missing v4 marker %v; addrs=%v",
			hostV4Marker, hostAddrs)
	}
	if !hostHasV6 {
		t.Errorf("host ferry NIC missing v6 marker %v; addrs=%v",
			hostV6Marker, hostAddrs)
	}
}

// ----- helpers --------------------------------------------------

func mustSubnet(p netip.Prefix) tcpip.Subnet {
	addrSlice := p.Masked().Addr().AsSlice()
	mask := make([]byte, len(addrSlice))
	bits := p.Bits()
	full := bits / 8
	rem := bits % 8
	for i := 0; i < full; i++ {
		mask[i] = 0xff
	}
	if rem > 0 && full < len(mask) {
		mask[full] = byte(0xff << uint(8-rem))
	}
	sn, err := tcpip.NewSubnet(tcpip.AddrFromSlice(addrSlice),
		tcpip.MaskFromBytes(mask))
	if err != nil {
		panic(err)
	}
	return sn
}

// Silence unused-warning during TDD red phase.
var _ = sync.Mutex{}
