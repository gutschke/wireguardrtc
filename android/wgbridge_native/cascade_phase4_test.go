// Phase 4 end-to-end tests for CASCADE-2.  Per the v3-review
// scope, these are gvisor-only — they exercise the full ferry +
// registry data path including AllowedIPs change events and the
// joiner-N rebuild gap, but skip real wireguard-go integration
// (deferred to Phase 5 real-device validation).
//
// What Phase 4 establishes:
//   - Registry-driven ferry creation actually carries packets
//     end-to-end across the two stacks.
//   - AllowedIPs change events rewire host-stack routes.
//   - During the joiner-N rebuild gap, traffic gets DROPPED at
//     the drop-NIC rather than leaked through the host stack's
//     default route.
//
// What Phase 4 does NOT exercise:
//   - Real WireGuard encryption / handshake (Phase 5).
//   - JNI surface (Phase 7).
//   - host_forwarder's default-route catchall behavior under
//     real load (Phase 5).

package main

import (
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	gvstack "gvisor.dev/gvisor/pkg/tcpip/stack"
)

// p4Rig is a Phase 4 test rig that combines a registry, a joiner
// stack with one extra "sink" NIC (representing a joiner peer's
// destination), and a host stack with a "source" NIC where we
// inject test packets.
type p4Rig struct {
	r             *CascadeFerryRegistry
	hostStack     *gvstack.Stack
	joinerStack   *gvstack.Stack
	hostSrcEp     *channel.Endpoint
	joinerSinkEp  *channel.Endpoint
	joinerSinkNIC tcpip.NICID
}

func newP4Rig(t *testing.T, joinerAllowedIPs, hostPeerSubnets []netip.Prefix) *p4Rig {
	t.Helper()
	r := newCascadeFerryRegistry()
	js := newJoinerStackForRegistry(t)
	hs := newHostStack(t)

	// Source NIC on host stack with markers so it's a valid
	// forwarding ingress.
	hostSrcEp := channel.New(64, 1500, "")
	const hostSrcNIC tcpip.NICID = 100
	if err := hs.CreateNIC(hostSrcNIC, hostSrcEp); err != nil {
		t.Fatalf("CreateNIC host: %s", err)
	}
	if err := bindStrongHostMarkers(hs, hostSrcNIC); err != nil {
		t.Fatalf("markers host: %s", err)
	}

	// Sink NIC on joiner stack (with markers).  Routes for
	// joinerAllowedIPs get installed BELOW the ferry route
	// because the ferry route is /24 (let's say) and the sink
	// route is /24 (same).  We use a more-specific /32 below.
	joinerSinkEp := channel.New(64, 1500, "")
	const joinerSinkNIC tcpip.NICID = 200
	if err := js.CreateNIC(joinerSinkNIC, joinerSinkEp); err != nil {
		t.Fatalf("CreateNIC joiner sink: %s", err)
	}
	if err := bindStrongHostMarkers(js, joinerSinkNIC); err != nil {
		t.Fatalf("markers joiner sink: %s", err)
	}
	// Route for each joinerAllowedIPs prefix points at the sink.
	for _, p := range joinerAllowedIPs {
		sn, _ := prefixToSubnet(p)
		js.AddRoute(tcpip.Route{Destination: sn, NIC: joinerSinkNIC})
	}

	// Register backends — order matters less than that BOTH end
	// up registered.
	r.RegisterJoinerStack(js, joinerAllowedIPs)
	r.RegisterHostBridge(1, hs, hostPeerSubnets)

	return &p4Rig{
		r:             r,
		hostStack:     hs,
		joinerStack:   js,
		hostSrcEp:     hostSrcEp,
		joinerSinkEp:  joinerSinkEp,
		joinerSinkNIC: joinerSinkNIC,
	}
}

func (rig *p4Rig) close() {
	rig.r.UnregisterHostBridge(1)
	rig.r.UnregisterJoinerStack()
	rig.hostStack.Close()
	rig.joinerStack.Close()
}

func (rig *p4Rig) waitForPacketOnSink(t *testing.T, d time.Duration) *gvstack.PacketBuffer {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if got := rig.joinerSinkEp.Read(); got != nil {
			return got
		}
		time.Sleep(time.Millisecond)
	}
	return nil
}

// 1. End-to-end: packet injected on host stack with dst in a
//    joiner AllowedIP traverses the cascade and arrives at the
//    joiner sink.
func TestCascadeEndToEndViaRegistry(t *testing.T) {
	rig := newP4Rig(t,
		[]netip.Prefix{netip.MustParsePrefix("10.50.0.0/24")},
		[]netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")})
	defer rig.close()

	src := netip.MustParseAddr("192.0.2.1")
	dst := netip.MustParseAddr("10.50.0.5")
	raw := craftIPv4UDP(src, dst, 1234, 53, []byte("phase4-e2e"))
	pkt := gvstack.NewPacketBuffer(gvstack.PacketBufferOptions{
		Payload: buffer.MakeWithData(raw),
	})
	rig.hostSrcEp.InjectInbound(header.IPv4ProtocolNumber, pkt)
	pkt.DecRef()

	got := rig.waitForPacketOnSink(t, 500*time.Millisecond)
	if got == nil {
		t.Fatalf("end-to-end cascade did not deliver packet")
	}
	got.DecRef()
}

// 2. AllowedIPs change: dynamically add a new prefix; packets to
//    addresses in the new prefix start flowing without a full
//    rebuild.
func TestCascadeAllowedIPsAddPropagates(t *testing.T) {
	rig := newP4Rig(t,
		[]netip.Prefix{netip.MustParsePrefix("10.50.0.0/24")},
		[]netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")})
	defer rig.close()

	// Add a new joiner-side route too, so the joiner stack
	// actually has somewhere to deliver the new-prefix packet.
	newPrefix := netip.MustParsePrefix("192.168.5.0/24")
	sn, _ := prefixToSubnet(newPrefix)
	rig.joinerStack.AddRoute(tcpip.Route{Destination: sn, NIC: rig.joinerSinkNIC})

	rig.r.OnJoinerAllowedIPsChanged([]netip.Prefix{
		netip.MustParsePrefix("10.50.0.0/24"),
		newPrefix,
	})

	src := netip.MustParseAddr("192.0.2.1")
	dst := netip.MustParseAddr("192.168.5.5")
	raw := craftIPv4UDP(src, dst, 1234, 53, []byte("new-prefix"))
	pkt := gvstack.NewPacketBuffer(gvstack.PacketBufferOptions{
		Payload: buffer.MakeWithData(raw),
	})
	rig.hostSrcEp.InjectInbound(header.IPv4ProtocolNumber, pkt)
	pkt.DecRef()

	got := rig.waitForPacketOnSink(t, 500*time.Millisecond)
	if got == nil {
		t.Fatalf("packet for newly-added cascade prefix did not arrive")
	}
	got.DecRef()
}

// 3. AllowedIPs change: remove a prefix; packets to addresses no
//    longer in cascade do NOT cross.
func TestCascadeAllowedIPsRemoveStopsForwarding(t *testing.T) {
	rig := newP4Rig(t,
		[]netip.Prefix{netip.MustParsePrefix("10.50.0.0/24")},
		[]netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")})
	defer rig.close()

	// Sanity: a packet works before the removal.
	rig.sendV4(t, "192.0.2.1", "10.50.0.5")
	if got := rig.waitForPacketOnSink(t, 200*time.Millisecond); got == nil {
		t.Fatalf("baseline cascade did not work")
	} else {
		got.DecRef()
	}

	// Remove the prefix.
	rig.r.OnJoinerAllowedIPsChanged([]netip.Prefix{})

	// New packet to the same dst should NOT arrive at the sink.
	rig.sendV4(t, "192.0.2.1", "10.50.0.5")
	if got := rig.waitForPacketOnSink(t, 200*time.Millisecond); got != nil {
		got.DecRef()
		t.Fatalf("packet arrived at sink after cascade prefix was removed")
	}
}

// 4. The CASCADE-2 §8 drop-NIC test: when the joiner stack
//    unregisters (simulating a rebuild gap), packets to cascade
//    prefixes are dropped at the host-stack drop-NIC rather than
//    falling through to any host-stack default route.
func TestCascadeRebuildGapDropsNotLeaks(t *testing.T) {
	rig := newP4Rig(t,
		[]netip.Prefix{netip.MustParsePrefix("10.50.0.0/24")},
		[]netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")})
	defer rig.close()

	// Install a "leak detector" NIC on host stack: a default
	// route to a separate sink endpoint.  If any packet escapes
	// the cascade route and falls through to default, we'll see
	// it here.
	leakEp := channel.New(64, 1500, "")
	const leakNIC tcpip.NICID = 300
	if err := rig.hostStack.CreateNIC(leakNIC, leakEp); err != nil {
		t.Fatalf("create leak detector NIC: %s", err)
	}
	if err := bindStrongHostMarkers(rig.hostStack, leakNIC); err != nil {
		t.Fatalf("markers leak detector NIC: %s", err)
	}
	rig.hostStack.AddRoute(tcpip.Route{
		Destination: header.IPv4EmptySubnet,
		NIC:         leakNIC,
	})

	// Unregister the joiner stack — simulate rebuild gap.
	rig.r.UnregisterJoinerStack()

	// Send a packet to a former-cascade prefix.
	rig.sendV4(t, "192.0.2.1", "10.50.0.5")

	// Wait — neither the joiner-side sink NOR the host-side leak
	// detector should see the packet.  The drop-NIC drops it.
	if got := rig.waitForPacketOnSink(t, 200*time.Millisecond); got != nil {
		got.DecRef()
		t.Fatalf("packet leaked to joiner sink during rebuild gap")
	}
	if got := leakEp.Read(); got != nil {
		got.DecRef()
		t.Fatalf("packet leaked to host-stack default route (leak detector) during rebuild gap")
	}

	// Now re-register: ferries should come back up and traffic
	// should flow again.
	rig.r.RegisterJoinerStack(rig.joinerStack,
		[]netip.Prefix{netip.MustParsePrefix("10.50.0.0/24")})

	rig.sendV4(t, "192.0.2.1", "10.50.0.6")
	if got := rig.waitForPacketOnSink(t, 500*time.Millisecond); got == nil {
		t.Fatalf("packet did not flow after rebuild-gap recovery")
	} else {
		got.DecRef()
	}
}

// 5. HostBridge unregister stops cascade for that bridge but leaves
//    other bridges working.  (Programmer-error invariants in the
//    plan prevent identical-prefix collisions, so we use disjoint
//    subnets per host bridge.)
func TestCascadeMultipleHostBridgesIsolated(t *testing.T) {
	r := newCascadeFerryRegistry()
	js := newJoinerStackForRegistry(t)
	defer js.Close()

	// Two host stacks.
	hs1 := newHostStack(t)
	defer hs1.Close()
	hs2 := newHostStack(t)
	defer hs2.Close()

	r.RegisterJoinerStack(js, []netip.Prefix{netip.MustParsePrefix("10.50.0.0/24")})
	r.RegisterHostBridge(1, hs1, []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")})
	r.RegisterHostBridge(2, hs2, []netip.Prefix{netip.MustParsePrefix("10.98.0.0/24")})

	if r.activeFerryCount() != 2 {
		t.Fatalf("expected 2 ferries; got %d", r.activeFerryCount())
	}

	r.UnregisterHostBridge(1)
	if r.activeFerryCount() != 1 {
		t.Fatalf("expected 1 ferry after unregister; got %d", r.activeFerryCount())
	}
}

// ----- helpers --------------------------------------------------

func (rig *p4Rig) sendV4(t *testing.T, src, dst string) {
	t.Helper()
	raw := craftIPv4UDP(
		netip.MustParseAddr(src),
		netip.MustParseAddr(dst),
		1234, 53, []byte("p4"))
	pkt := gvstack.NewPacketBuffer(gvstack.PacketBufferOptions{
		Payload: buffer.MakeWithData(raw),
	})
	rig.hostSrcEp.InjectInbound(header.IPv4ProtocolNumber, pkt)
	pkt.DecRef()
}

// Silence imports we use indirectly.
var _ = ipv4.NewProtocol
var _ = ipv6.NewProtocol
