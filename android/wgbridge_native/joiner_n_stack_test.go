// D4.J1 tests for the joiner-N shared netstack scaffolding.
// Builds on D4.P1's `joiner_n_router_spike_test.go` — those probes
// validated raw gvisor multi-NIC routing; these tests validate
// the *production* surface (attachNic / detachNic / addRoute /
// addJoinerRoutes) without touching wireguard-go or kernel TUN.

package main

import (
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// helper — push an IPv4 UDP packet at [nicID]'s inbound side.
func injectV4(ep *channel.Endpoint, src, dst netip.Addr, body []byte) {
	raw := craftIPv4UDP(src, dst, 1234, 53, body)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(raw),
	})
	defer pkt.DecRef()
	ep.InjectInbound(header.IPv4ProtocolNumber, pkt)
}

func readOutbound(t *testing.T, ep *channel.Endpoint, d time.Duration) *stack.PacketBuffer {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if pkt := ep.Read(); pkt != nil {
			return pkt
		}
		time.Sleep(time.Millisecond)
	}
	return nil
}

func dstOfPkt(t *testing.T, pkt *stack.PacketBuffer) netip.Addr {
	t.Helper()
	v := pkt.ToView()
	defer v.Release()
	raw := make([]byte, v.Size())
	if _, err := v.Read(raw); err != nil {
		t.Fatalf("view read: %v", err)
	}
	hdr := header.IPv4(raw)
	dst := hdr.DestinationAddress().As4()
	return netip.AddrFrom4(dst)
}

// 1. Fresh stack opens cleanly + closes cleanly.
func TestJ1NewAndCloseSharedStack(t *testing.T) {
	ss, err := newSharedStack(1500)
	if err != nil {
		t.Fatalf("newSharedStack: %v", err)
	}
	// Idempotent close.
	ss.close()
	ss.close()
}

// 2. Handle allocation + lookup are stable.
func TestJ1HandleAllocationRoundtrip(t *testing.T) {
	a, _ := newSharedStack(1500)
	defer a.close()
	b, _ := newSharedStack(1500)
	defer b.close()
	ha := allocateSharedStackHandle(a)
	hb := allocateSharedStackHandle(b)
	if ha == hb {
		t.Fatalf("allocateSharedStackHandle reused %d", ha)
	}
	if lookupSharedStack(ha) != a {
		t.Fatalf("lookup(ha) didn't return a")
	}
	if lookupSharedStack(hb) != b {
		t.Fatalf("lookup(hb) didn't return b")
	}
	if freeSharedStack(ha) != a {
		t.Fatalf("freeSharedStack(ha) didn't return a")
	}
	if lookupSharedStack(ha) != nil {
		t.Fatalf("ha still present after free")
	}
}

// 3. Attaching a NIC returns a valid (id, endpoint) pair and the
// gvisor stack knows about the NIC afterwards.
func TestJ1AttachNicReturnsValidEndpoint(t *testing.T) {
	ss, _ := newSharedStack(1500)
	defer ss.close()
	nicID, ep, err := ss.attachNic()
	if err != nil {
		t.Fatalf("attachNic: %v", err)
	}
	if ep == nil {
		t.Fatalf("attachNic returned nil endpoint")
	}
	if nicID < firstJoinerNicID {
		t.Fatalf("attachNic returned NIC ID %d < firstJoinerNicID %d",
			nicID, firstJoinerNicID)
	}
	// Stack should be aware of this NIC.
	infos := ss.stack.NICInfo()
	if _, ok := infos[nicID]; !ok {
		t.Fatalf("stack.NICInfo missing NIC %d after attach: %v", nicID, infos)
	}
}

// 4. Detach removes the NIC from the stack; double-detach is a
// no-op.
func TestJ1DetachNicIsIdempotent(t *testing.T) {
	ss, _ := newSharedStack(1500)
	defer ss.close()
	nicID, _, _ := ss.attachNic()
	if err := ss.detachNic(nicID); err != nil {
		t.Fatalf("first detach: %v", err)
	}
	if err := ss.detachNic(nicID); err != nil {
		t.Fatalf("second detach should be a no-op, got: %v", err)
	}
	if _, ok := ss.stack.NICInfo()[nicID]; ok {
		t.Fatalf("NIC %d still present in stack after detach", nicID)
	}
}

// 5. NIC IDs are monotonic — detaching and reattaching gives a
// fresh ID, never reuses. This protects against stale routes
// silently rebinding to a different joiner.
func TestJ1NicIdsAreMonotonic(t *testing.T) {
	ss, _ := newSharedStack(1500)
	defer ss.close()
	id1, _, _ := ss.attachNic()
	_ = ss.detachNic(id1)
	id2, _, _ := ss.attachNic()
	if id2 <= id1 {
		t.Fatalf("NIC IDs went backwards after detach: %d → %d", id1, id2)
	}
}

// 6. addRoute on an unknown NIC fails loudly (caller has the
// info — typo / use-after-detach — that gvisor would otherwise
// silently swallow).
func TestJ1AddRouteRejectsUnknownNic(t *testing.T) {
	ss, _ := newSharedStack(1500)
	defer ss.close()
	prefix := netip.MustParsePrefix("10.1.0.0/16")
	err := ss.addRoute(prefix, tcpip.NICID(999))
	if err == nil {
		t.Fatalf("addRoute to NIC 999 should have errored")
	}
}

// 7. A two-NIC routing scenario: app-side NIC injects a packet
// with dst inside the joiner's AllowedIPs; the packet comes out
// the joiner's NIC. Mirrors the P1 spike but uses the production
// API (attachNic + addRoute) end-to-end.
func TestJ1ProductionApiRoutesAppsToJoiner(t *testing.T) {
	ss, _ := newSharedStack(1500)
	defer ss.close()
	// "kernel-TUN" NIC — in production this is NIC 1, attached by
	// D4.J2 via a special helper. For J1's test, just attachNic
	// twice and call the first one the kernel-TUN side.
	tunID, tunEp, err := ss.attachNic()
	if err != nil {
		t.Fatalf("attach tun NIC: %v", err)
	}
	joinerID, joinerEp, err := ss.attachNic()
	if err != nil {
		t.Fatalf("attach joiner NIC: %v", err)
	}
	// Route: apps' traffic for 10.99.0.0/24 should go out the
	// joiner's NIC.
	if err := ss.addRoute(
		netip.MustParsePrefix("10.99.0.0/24"), joinerID,
	); err != nil {
		t.Fatalf("addRoute: %v", err)
	}

	// Inject as if the kernel TUN had just delivered this packet.
	src := netip.MustParseAddr("192.0.2.1")
	dst := netip.MustParseAddr("10.99.0.5")
	injectV4(tunEp, src, dst, []byte("hello"))

	got := readOutbound(t, joinerEp, 500*time.Millisecond)
	if got == nil {
		t.Fatalf("packet didn't reach joiner NIC")
	}
	defer got.DecRef()
	if d := dstOfPkt(t, got); d != dst {
		t.Fatalf("dst mismatch: got %v, want %v", d, dst)
	}
	_ = tunID
}

// 8. Inbound routing: joiner-side NIC injects a packet with dst
// = joiner's interface address (e.g. 10.99.0.2); it should come
// out the kernel-TUN NIC. This is the "wg-go decrypted a reply
// for the app" path.
func TestJ1ProductionApiRoutesJoinerToApps(t *testing.T) {
	ss, _ := newSharedStack(1500)
	defer ss.close()
	tunID, tunEp, _ := ss.attachNic()
	joinerID, joinerEp, _ := ss.attachNic()

	// Route: traffic destined for 10.99.0.2/32 (joiner's
	// interface address) → kernel-TUN NIC.
	if err := ss.addRoute(
		netip.MustParsePrefix("10.99.0.2/32"), tunID,
	); err != nil {
		t.Fatalf("addRoute: %v", err)
	}

	// Inject from the joiner side.
	src := netip.MustParseAddr("10.99.0.5")
	dst := netip.MustParseAddr("10.99.0.2")
	injectV4(joinerEp, src, dst, []byte("reply"))

	got := readOutbound(t, tunEp, 500*time.Millisecond)
	if got == nil {
		t.Fatalf("inbound packet didn't reach kernel-TUN NIC")
	}
	defer got.DecRef()
	if d := dstOfPkt(t, got); d != dst {
		t.Fatalf("dst mismatch: got %v, want %v", d, dst)
	}
	_ = joinerID
}

// 9. addJoinerRoutes — the higher-level helper. Programs BOTH
// directions in one call. Requires NIC 1 (reservedKernelTunNicID)
// to exist, else the interface-addr side fails.
func TestJ1AddJoinerRoutesWiresBothDirections(t *testing.T) {
	ss, _ := newSharedStack(1500)
	defer ss.close()
	// Pre-attach NIC 1 as the kernel-TUN side via the dedicated
	// helper. Production D4.J2 will additionally wire a read pump
	// to this endpoint; the routing wiring itself doesn't need the
	// pump.
	tunID, tunEp, err := ss.attachKernelTunNic()
	if err != nil {
		t.Fatalf("attachKernelTunNic: %v", err)
	}
	if tunID != reservedKernelTunNicID {
		t.Fatalf("kernel-tun NIC got id %d, want reserved %d",
			tunID, reservedKernelTunNicID)
	}
	joinerID, joinerEp, _ := ss.attachNic()

	err = ss.addJoinerRoutes(
		joinerID,
		[]netip.Prefix{
			netip.MustParsePrefix("10.99.0.0/24"),
			netip.MustParsePrefix("172.16.0.0/12"),
		},
		[]netip.Prefix{
			netip.MustParsePrefix("10.99.0.2/32"),
		},
	)
	if err != nil {
		t.Fatalf("addJoinerRoutes: %v", err)
	}

	// Outbound check: app → joiner.
	injectV4(tunEp,
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("172.16.5.5"),
		[]byte("out"),
	)
	if got := readOutbound(t, joinerEp, 500*time.Millisecond); got == nil {
		t.Fatalf("outbound 172.16.5.5 didn't reach joiner")
	} else {
		got.DecRef()
	}

	// Inbound check: joiner → app.
	injectV4(joinerEp,
		netip.MustParseAddr("10.99.0.5"),
		netip.MustParseAddr("10.99.0.2"),
		[]byte("in"),
	)
	if got := readOutbound(t, tunEp, 500*time.Millisecond); got == nil {
		t.Fatalf("inbound to 10.99.0.2 didn't reach kernel-TUN")
	} else {
		got.DecRef()
	}
}

// 10. Multi-joiner routing — two joiners with disjoint
// AllowedIPs; packets must demux without cross-talk. Mirrors the
// P1 cross-talk probe but through the production API.
func TestJ1TwoJoinersDemuxedWithoutCrossTalk(t *testing.T) {
	ss, _ := newSharedStack(1500)
	defer ss.close()
	_, tunEp, _ := ss.attachNic()
	jA, epA, _ := ss.attachNic()
	jB, epB, _ := ss.attachNic()
	if err := ss.addRoute(
		netip.MustParsePrefix("10.1.0.0/16"), jA,
	); err != nil {
		t.Fatalf("route A: %v", err)
	}
	if err := ss.addRoute(
		netip.MustParsePrefix("10.2.0.0/16"), jB,
	); err != nil {
		t.Fatalf("route B: %v", err)
	}

	injectV4(tunEp,
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("10.1.0.7"),
		[]byte("a"),
	)
	got := readOutbound(t, epA, 500*time.Millisecond)
	if got == nil {
		t.Fatalf("packet for 10.1.0.7 didn't reach joiner A")
	}
	got.DecRef()
	// joiner B must NOT have received it.
	if leak := readOutbound(t, epB, 50*time.Millisecond); leak != nil {
		leak.DecRef()
		t.Fatalf("cross-talk: packet for joiner A leaked to joiner B")
	}

	injectV4(tunEp,
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("10.2.0.7"),
		[]byte("b"),
	)
	got = readOutbound(t, epB, 500*time.Millisecond)
	if got == nil {
		t.Fatalf("packet for 10.2.0.7 didn't reach joiner B")
	}
	got.DecRef()
	if leak := readOutbound(t, epA, 50*time.Millisecond); leak != nil {
		leak.DecRef()
		t.Fatalf("cross-talk: packet for joiner B leaked to joiner A")
	}
}

// 11. Detaching a joiner mid-flight — packets still in flight
// for that joiner get dropped silently; surviving joiners keep
// working. This is the "user removed tunnel N+1" case.
func TestJ1DetachLeavesOtherJoinersAlive(t *testing.T) {
	ss, _ := newSharedStack(1500)
	defer ss.close()
	_, tunEp, _ := ss.attachNic()
	jA, epA, _ := ss.attachNic()
	jB, epB, _ := ss.attachNic()
	_ = ss.addRoute(netip.MustParsePrefix("10.1.0.0/16"), jA)
	_ = ss.addRoute(netip.MustParsePrefix("10.2.0.0/16"), jB)

	// Verify both joiners alive first.
	injectV4(tunEp,
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("10.1.0.7"),
		[]byte("a"),
	)
	if got := readOutbound(t, epA, 500*time.Millisecond); got == nil {
		t.Fatalf("joiner A baseline broken")
	} else {
		got.DecRef()
	}

	// Detach B.
	if err := ss.detachNic(jB); err != nil {
		t.Fatalf("detach jB: %v", err)
	}

	// A still works.
	injectV4(tunEp,
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("10.1.0.7"),
		[]byte("a2"),
	)
	if got := readOutbound(t, epA, 500*time.Millisecond); got == nil {
		t.Fatalf("joiner A stopped working after unrelated joiner B was detached")
	} else {
		got.DecRef()
	}
	_ = epB
}

// 12. closing the stack invalidates further operations cleanly.
func TestJ1OperationsAfterCloseReturnError(t *testing.T) {
	ss, _ := newSharedStack(1500)
	ss.close()
	if _, _, err := ss.attachNic(); err == nil {
		t.Fatalf("attachNic after close should have failed")
	}
}
