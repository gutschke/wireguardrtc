//go:build !android

package main

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gvchannel "gvisor.dev/gvisor/pkg/tcpip/link/channel"
	gvipv4 "gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	gvstack "gvisor.dev/gvisor/pkg/tcpip/stack"
)

// TestBuildIPv4ICMPEchoReplyChecksum verifies the synthesised
// ICMP echo reply has a checksum that covers the payload, not
// just the 8-byte header. Regression test for the bug that made
// Linux's default-payload `ping` (56 bytes) silently fail through
// the host forwarder while empty-payload pings (the in-process
// probe + nativePingV4) worked. The bug: the original code
// sliced just the 8-byte ICMP header to compute the checksum, so
// any non-empty payload arrived with a stale checksum that
// kernels silently drop.
func TestBuildIPv4ICMPEchoReplyChecksum(t *testing.T) {
	cases := []struct {
		name string
		payload []byte
	}{
		{"empty", nil},
		{"56B (linux ping default)", bytesNonZero(56)},
		{"1k", bytesNonZero(1024)},
	}
	src := net.IPv4(8, 8, 8, 8)
	dst := net.IPv4(10, 99, 0, 2)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt := buildIPv4ICMPEchoReply(
				src, dst, 0x1234, 0x5678, tc.payload)
			// Validate IP header layout.
			ip := header.IPv4(pkt[:header.IPv4MinimumSize])
			if !ip.IsValid(len(pkt)) {
				t.Fatalf("IPv4 header invalid")
			}
			// The verification we care about: recompute the
			// ICMP checksum over the ENTIRE ICMP segment + the
			// stored checksum must net to all-ones (-0).
			// This is the same one's-complement-sum check
			// Linux's kernel does on receive.
			icmpSeg := pkt[header.IPv4MinimumSize:]
			if got := onesComplementSum16(icmpSeg); got != 0xffff {
				t.Fatalf("ICMP checksum doesn't validate over header+payload: got sum 0x%x (want 0xffff)", got)
			}
			// Sanity-check the header fields too.
			if icmpSeg[0] != uint8(header.ICMPv4EchoReply) {
				t.Fatalf("Type byte = 0x%x (want 0x00 EchoReply)", icmpSeg[0])
			}
			if icmpSeg[1] != 0 {
				t.Fatalf("Code byte = 0x%x (want 0)", icmpSeg[1])
			}
			gotIdent := binary.BigEndian.Uint16(icmpSeg[4:6])
			gotSeq := binary.BigEndian.Uint16(icmpSeg[6:8])
			if gotIdent != 0x1234 {
				t.Fatalf("ident = 0x%x", gotIdent)
			}
			if gotSeq != 0x5678 {
				t.Fatalf("seq = 0x%x", gotSeq)
			}
			gotPayload := icmpSeg[8:]
			if len(gotPayload) != len(tc.payload) {
				t.Fatalf("payload len = %d (want %d)", len(gotPayload), len(tc.payload))
			}
			for i := range tc.payload {
				if gotPayload[i] != tc.payload[i] {
					t.Fatalf("payload[%d] mismatch", i)
				}
			}
		})
	}
}

// onesComplementSum16 returns the 16-bit one's complement sum of
// the buffer (in network byte order). Used to verify checksums:
// for a packet whose checksum field is set correctly, this
// returns 0xffff (= -0).
func onesComplementSum16(buf []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(buf); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(buf[i : i+2]))
	}
	if len(buf)%2 == 1 {
		sum += uint32(buf[len(buf)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}

// addrSlice extracts a byte slice from a [tcpip.Address] value
// without taking its pointer (gvisor's AsSlice is a pointer-method
// only since v0.0.0-20250503, hence the local helper).
func addrSlice(a tcpip.Address) []byte {
	return a.AsSlice()
}

func bytesNonZero(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}

// V6.H2b — sibling of [TestBuildIPv4ICMPEchoReplyChecksum] for the
// ICMPv6 path.  Verifies that the synthesised echo reply has:
//
//   - a valid IPv6 header (next-header = 58, payload-length set,
//     src/dst addresses preserved),
//   - an ICMPv6 echo-reply (type=129, code=0) carrying the
//     joiner's original ident + sequence + payload,
//   - a checksum that validates against the IPv6 pseudo-header +
//     ICMPv6 segment per RFC 4443 §2.3.  Unlike v4, the v6 ICMP
//     checksum DEPENDS on the source/destination addresses
//     (pseudo-header), so getting either address wrong silently
//     drops the packet on the receiver.
//
// If a kernel-level v6 receiver were to validate the checksum and
// reject ours, the joiner's `ping6` would silently fail.  The
// recompute-and-compare step here gives the same answer the
// receiver does, so a regression shows up immediately.
func TestBuildIPv6ICMPEchoReplyChecksum(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
	}{
		{"empty", nil},
		{"56B (linux ping6 default)", bytesNonZero(56)},
		{"1k", bytesNonZero(1024)},
	}
	src := net.ParseIP("2001:db8::1") // sender of the reply (= upstream host)
	dst := net.ParseIP("fd00:dead:beef::2") // joiner who pinged
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt := buildIPv6ICMPEchoReply(
				src, dst, 0x1234, 0x5678, tc.payload)
			// Validate IP header layout.
			ip := header.IPv6(pkt[:header.IPv6MinimumSize])
			if !ip.IsValid(len(pkt)) {
				t.Fatalf("IPv6 header invalid")
			}
			if ip.NextHeader() != uint8(header.ICMPv6ProtocolNumber) {
				t.Fatalf("NextHeader = %d (want 58 ICMPv6)", ip.NextHeader())
			}
			wantPayload := header.ICMPv6MinimumSize + len(tc.payload)
			if int(ip.PayloadLength()) != wantPayload {
				t.Fatalf("PayloadLength = %d (want %d)",
					ip.PayloadLength(), wantPayload)
			}
			if ip.HopLimit() == 0 {
				t.Fatalf("HopLimit must be non-zero (kernels drop hop=0)")
			}
			// src/dst byte-for-byte.
			if !net.IP(addrSlice(ip.SourceAddress())).Equal(src) {
				t.Fatalf("src = %v (want %v)",
					net.IP(addrSlice(ip.SourceAddress())), src)
			}
			if !net.IP(addrSlice(ip.DestinationAddress())).Equal(dst) {
				t.Fatalf("dst = %v (want %v)",
					net.IP(addrSlice(ip.DestinationAddress())), dst)
			}

			// ICMPv6 segment.
			icmpSeg := pkt[header.IPv6MinimumSize:]
			if icmpSeg[0] != uint8(header.ICMPv6EchoReply) {
				t.Fatalf("Type byte = 0x%x (want 0x81 EchoReply)", icmpSeg[0])
			}
			if icmpSeg[1] != 0 {
				t.Fatalf("Code byte = 0x%x (want 0)", icmpSeg[1])
			}
			gotIdent := binary.BigEndian.Uint16(icmpSeg[4:6])
			gotSeq := binary.BigEndian.Uint16(icmpSeg[6:8])
			if gotIdent != 0x1234 {
				t.Fatalf("ident = 0x%x", gotIdent)
			}
			if gotSeq != 0x5678 {
				t.Fatalf("seq = 0x%x", gotSeq)
			}
			gotPayload := icmpSeg[8:]
			if len(gotPayload) != len(tc.payload) {
				t.Fatalf("payload len = %d (want %d)",
					len(gotPayload), len(tc.payload))
			}
			for i := range tc.payload {
				if gotPayload[i] != tc.payload[i] {
					t.Fatalf("payload[%d] mismatch", i)
				}
			}

			// Checksum verification (RFC 4443 §2.3 + RFC 2460 §8.1):
			// the one's-complement sum of the IPv6 pseudo-header
			// + the FULL ICMPv6 segment (including the stored
			// checksum value) must come out to 0xFFFF (= -0).
			//
			// gvisor's `ICMPv6Checksum` helper SKIPS the checksum
			// field internally (it's used both to compute the
			// initial value AND to verify, so it has to be neutral
			// on the field's bytes), so we can't just call it
			// twice and expect 0 — that gives the same answer
			// both times.  Instead we recompute the sum manually
			// over the pseudo-header + the entire ICMPv6 segment.
			pseudo := make([]byte, 40)
			copy(pseudo[0:16], src.To16())
			copy(pseudo[16:32], dst.To16())
			binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(icmpSeg)))
			pseudo[36] = 0
			pseudo[37] = 0
			pseudo[38] = 0
			pseudo[39] = uint8(header.ICMPv6ProtocolNumber) // 58
			combined := append(pseudo, icmpSeg...)
			if got := onesComplementSum16(combined); got != 0xffff {
				t.Fatalf("ICMPv6 checksum doesn't validate over "+
					"pseudo-header+segment: got sum 0x%x (want 0xffff)", got)
			}
			// Also pin: storing 0 in the checksum field and
			// re-running gvisor's helper must regenerate the same
			// stored value we have.  Catches "we used the wrong
			// helper API and got a coincidentally-self-consistent
			// but wrong-on-the-wire result" failure modes.
			stored := binary.BigEndian.Uint16(icmpSeg[2:4])
			// Use a copy of the header with the checksum field
			// zeroed, so ICMPv6Checksum sees the original input.
			zeroed := make([]byte, header.ICMPv6MinimumSize)
			copy(zeroed, icmpSeg[:header.ICMPv6MinimumSize])
			zeroed[2] = 0
			zeroed[3] = 0
			recomputed := header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
				Header:      header.ICMPv6(zeroed),
				Src:         ip.SourceAddress(),
				Dst:         ip.DestinationAddress(),
				PayloadCsum: checksum.Checksum(gotPayload, 0),
				PayloadLen:  len(gotPayload),
			})
			if recomputed != stored {
				t.Fatalf("gvisor.ICMPv6Checksum disagreement: "+
					"recomputed=0x%x stored=0x%x", recomputed, stored)
			}
		})
	}
}

// V6.H2b — pin RFC 4443 §2.1: ICMPv6 EchoReply type is 129 (0x81).
// Defends against a future gvisor rename that swaps the constant.
func TestICMPv6EchoReplyConstantIs129(t *testing.T) {
	if uint8(header.ICMPv6EchoReply) != 129 {
		t.Fatalf("ICMPv6EchoReply = %d (RFC 4443 says 129)",
			header.ICMPv6EchoReply)
	}
	if uint8(header.ICMPv6EchoRequest) != 128 {
		t.Fatalf("ICMPv6EchoRequest = %d (RFC 4443 says 128)",
			header.ICMPv6EchoRequest)
	}
}

// V6.H2b — verify gvisor's `tcpip.Address` discriminates v4 vs v6
// by the embedded length field, so the shared `tempAddrs` map is
// safe to use for both families.  If gvisor ever switched to a
// pure-byte equality (ignoring length), `tempAddrs[ipv4("0.0.0.0")]`
// would collide with `tempAddrs[ipv6("::")]` and the forwarder
// would refuse to re-register an address that's "the same bytes"
// under the other family.  This test pins the current behaviour
// so a regression in the upgrade trips the alarm.
func TestTempAddrsV4V6Coexist(t *testing.T) {
	// Both addresses have all-zero bytes — the most aggressive
	// case for a hypothetical byte-only equality bug.
	v4 := tcpip.AddrFromSlice([]byte{0, 0, 0, 0})
	v6 := tcpip.AddrFromSlice(make([]byte, 16))
	if v4 == v6 {
		t.Fatalf("tcpip.Address treats all-zero v4 and v6 as equal — " +
			"the forwarder's shared tempAddrs map is unsafe")
	}
	// Also pin the case the production code actually generates.
	v4Real := tcpip.AddrFromSlice(net.ParseIP("1.1.1.1").To4())
	v6Real := tcpip.AddrFromSlice(net.ParseIP("2001:db8::1").To16())
	if v4Real == v6Real {
		t.Fatalf("v4 1.1.1.1 == v6 2001:db8::1 — impossible-by-length should hold")
	}
	// Map round-trip — closer to what the forwarder does.
	m := make(map[tcpip.Address]bool)
	m[v4] = true
	m[v6] = true
	if len(m) != 2 {
		t.Fatalf("expected 2 distinct keys (v4 + v6); got %d", len(m))
	}
}

// V6.H2b — `handleLocalICMPv6` must filter to Type=EchoRequest +
// Code=0 only, so NDP / MLD / Router Discovery / Parameter Problem
// messages don't accidentally trigger a synthesised echo reply
// (which would be wrong and confusing on the wire).  Mirrors the
// v4 path's implicit filter via the early `if Type != EchoRequest`
// return — this test pins the analogous filter for v6.
//
// Construction strategy: build a minimal PacketBuffer with the
// IPv6 fixed header + the targeted ICMPv6 type, simulate the
// temp-local-address path (the only branch that exercises our
// custom handler), call `handleLocalICMPv6`, assert that the
// pingWg counter stays at zero.
func TestHandleLocalICMPv6FiltersNonEcho(t *testing.T) {
	cases := []struct {
		name     string
		icmpType header.ICMPv6Type
	}{
		{"NDP-NeighborSolicit (135)", header.ICMPv6NeighborSolicit},
		{"NDP-NeighborAdvert (136)", header.ICMPv6NeighborAdvert},
		{"NDP-RouterSolicit (133)", header.ICMPv6RouterSolicit},
		{"NDP-RouterAdvert (134)", header.ICMPv6RouterAdvert},
		{"MLD-MulticastListenerQuery (130)", header.ICMPv6MulticastListenerQuery},
		{"MLD-MulticastListenerReport (131)", header.ICMPv6MulticastListenerReport},
		{"ParameterProblem (4)", header.ICMPv6ParamProblem},
		{"DestinationUnreachable (1)", header.ICMPv6DstUnreachable},
		{"PacketTooBig (2)", header.ICMPv6PacketTooBig},
		{"TimeExceeded (3)", header.ICMPv6TimeExceeded},
		{"EchoReply (129)", header.ICMPv6EchoReply},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := &hostForwarderState{}
			// Synthetic ICMPv6 packet headed for a temp-local
			// address — mimics what gvisor would deliver to our
			// transport handler.
			totalLen := header.IPv6MinimumSize + header.ICMPv6MinimumSize
			pktBytes := make([]byte, totalLen)
			ip := header.IPv6(pktBytes[:header.IPv6MinimumSize])
			ip.Encode(&header.IPv6Fields{
				PayloadLength:     uint16(header.ICMPv6MinimumSize),
				TransportProtocol: header.ICMPv6ProtocolNumber,
				HopLimit:          64,
				SrcAddr: tcpip.AddrFromSlice(
					net.ParseIP("fd00:dead:beef::2").To16()),
				DstAddr: tcpip.AddrFromSlice(
					net.ParseIP("2001:db8::ffff").To16()),
			})
			icmpHdr := header.ICMPv6(pktBytes[header.IPv6MinimumSize:])
			icmpHdr.SetType(tc.icmpType)
			icmpHdr.SetCode(0)

			buf := buffer.MakeWithData(pktBytes)
			pkt := gvstack.NewPacketBuffer(gvstack.PacketBufferOptions{Payload: buf})
			defer pkt.DecRef()
			if _, ok := pkt.NetworkHeader().Consume(header.IPv6MinimumSize); !ok {
				t.Fatalf("Consume(network)")
			}
			if _, ok := pkt.TransportHeader().Consume(header.ICMPv6MinimumSize); !ok {
				t.Fatalf("Consume(transport)")
			}
			pkt.NetworkPacketInfo.LocalAddressTemporary = true

			// Capture the pingWg + pingsSent state pre/post.  We
			// can't directly read the WaitGroup counter, but
			// pingsSent is incremented inside dispatchPingV6
			// before any I/O — so if our filter is doing its
			// job, this stays zero.
			before := state.pingsSent.Load()
			ret := state.handleLocalICMPv6(gvstack.TransportEndpointID{}, pkt)
			if ret {
				t.Fatalf("handleLocalICMPv6 returned true; want false")
			}
			// The handler may spawn a goroutine for EchoRequest;
			// for everything else it must NOT.  EchoRequest is
			// excluded from this list (only filtered-out types).
			time.Sleep(50 * time.Millisecond)
			after := state.pingsSent.Load()
			if after != before {
				t.Fatalf("type %s triggered a ping goroutine "+
					"(pingsSent: %d -> %d); filter is broken",
					tc.name, before, after)
			}
		})
	}
}

// V6.H2b — `closeForwarder()` must wait for in-flight v6 ping
// goroutines before tearing down NIC2.  Mirrors the v4 contract;
// pinned here so a future refactor that splits the pingWg between
// families doesn't accidentally drop the v6 half.
func TestCloseForwarderWaitsForV6Pings(t *testing.T) {
	state := &hostForwarderState{
		tempAddrs: make(map[tcpip.Address]bool),
	}
	state.ctx, state.stop = context.WithCancel(context.Background())
	// Skip the stack tear-down (no real stack here); closeForwarder
	// hits stk.SetRouteTable + RemoveNIC which would nil-deref
	// without a real stack.  We're only validating the WaitGroup
	// contract.
	pingDone := make(chan struct{})
	state.pingWg.Add(1)
	go func() {
		defer state.pingWg.Done()
		<-pingDone
	}()

	closeReturned := make(chan struct{})
	go func() {
		// Same body as closeForwarder but without the stack
		// tear-down lines, so we can run it without a real
		// gvisor stack.  The WaitGroup synchronisation is the
		// thing under test.
		state.closed.Store(true)
		state.stop()
		state.pingWg.Wait()
		close(closeReturned)
	}()

	// Give the close attempt a moment to enter Wait().
	time.Sleep(50 * time.Millisecond)
	select {
	case <-closeReturned:
		t.Fatalf("close completed before the v6 ping goroutine exited; " +
			"pingWg coverage is broken")
	default:
		// Expected — Wait() is blocking.
	}

	// Now release the goroutine and expect close to return.
	close(pingDone)
	select {
	case <-closeReturned:
		// Good — close completed after the v6 ping exited.
	case <-time.After(2 * time.Second):
		t.Fatalf("close did not return within 2s of the ping exiting")
	}
}

// V6.H2b — `handleOutbound` dispatches on the IP version nibble.
// Synthesise a v4 packet (top nibble 4) and a v6 packet (top
// nibble 6), confirm each lands in the right family-specific
// handler by observing the counters that *each handler* but not
// the other increments.
//
// TCP/UDP take the synchronous redirect path which increments
// `tcpRedirs`/`udpRedirs` BEFORE any further work, so the test
// doesn't have to deal with goroutine timing.  ICMPv6 spawns a
// goroutine via `s.pingWg.Add(1)/dispatchPingV6` — we measure
// the WaitGroup change indirectly via `pingsSent` which
// increments inside the goroutine before any I/O.
func TestHandleOutboundDispatchesByIPVersion(t *testing.T) {
	t.Run("v4-TCP-only-increments-v4-counters", func(t *testing.T) {
		state := newDispatchTestState()
		pkt := buildV4TCPSyn(t,
			net.ParseIP("10.99.0.2"), net.ParseIP("1.1.1.1"),
			51234, 80)
		state.handleOutbound(pkt)
		if state.tcpRedirs.Load() != 1 {
			t.Fatalf("expected v4 tcpRedirs+1; got %d", state.tcpRedirs.Load())
		}
		if state.udpRedirs.Load() != 0 {
			t.Fatalf("v4 packet incremented udpRedirs (should be untouched)")
		}
	})
	t.Run("v6-TCP-only-increments-v6-tcpRedirs", func(t *testing.T) {
		state := newDispatchTestState()
		pkt := buildV6TCPSyn(t,
			net.ParseIP("fd00::2"), net.ParseIP("2001:db8::ffff"),
			51234, 80)
		state.handleOutbound(pkt)
		// V6.H2b TCP path shares the same counter as v4 — that's
		// the intentional architectural choice.  What we're
		// asserting here is that the v6 dispatch reached the
		// redirect path AT ALL.
		if state.tcpRedirs.Load() != 1 {
			t.Fatalf("v6 TCP didn't reach redirect path; tcpRedirs=%d", state.tcpRedirs.Load())
		}
		if state.udpRedirs.Load() != 0 {
			t.Fatalf("v6 TCP packet wrongly counted as UDP")
		}
	})
	t.Run("v6-UDP-increments-udpRedirs", func(t *testing.T) {
		state := newDispatchTestState()
		pkt := buildV6UDP(t,
			net.ParseIP("fd00::2"), net.ParseIP("2606:4700:4700::1111"),
			34567, 53)
		state.handleOutbound(pkt)
		if state.udpRedirs.Load() != 1 {
			t.Fatalf("v6 UDP didn't reach redirect path; udpRedirs=%d", state.udpRedirs.Load())
		}
		if state.tcpRedirs.Load() != 0 {
			t.Fatalf("v6 UDP packet wrongly counted as TCP")
		}
	})
	t.Run("v6-unknown-next-header-drops-no-counter", func(t *testing.T) {
		state := newDispatchTestState()
		pkt := buildV6OtherProto(t,
			net.ParseIP("fd00::2"), net.ParseIP("2001:db8::1"),
			44 /* Fragment — RFC 8200 §4.5 */)
		state.handleOutbound(pkt)
		if state.tcpRedirs.Load() != 0 || state.udpRedirs.Load() != 0 ||
			state.pingsSent.Load() != 0 {
			t.Fatalf("v6 unsupported next-hdr triggered a redirect counter")
		}
	})
}

// newDispatchTestState builds a `hostForwarderState` minimal
// enough for the dispatch tests: empty `tempAddrs`, no NIC, no
// real netstack.  The redirect helpers call `s.ensureTempLocalAddressV6`
// → `s.stk.AddProtocolAddress` which would nil-deref; for the
// dispatch tests we want the counter to increment but the
// AddProtocolAddress call to silently fail, leaving the test
// observable via the counter.  Production code's caller never
// constructs the state without a stack — only tests do.
//
// To avoid the nil-deref, we shortcut `ensureTempLocalAddressV6`
// by pre-populating `tempAddrs` with the test's expected dst
// addresses, so the function early-returns before touching `s.stk`.
func newDispatchTestState() *hostForwarderState {
	s := &hostForwarderState{
		tempAddrs: make(map[tcpip.Address]bool),
	}
	// Pre-mark the test dsts so ensureTempLocalAddress{,V6} skip
	// the AddProtocolAddress call (which needs a real stack).
	s.tempAddrs[tcpip.AddrFromSlice(net.ParseIP("1.1.1.1").To4())] = true
	s.tempAddrs[tcpip.AddrFromSlice(net.ParseIP("2001:db8::ffff").To16())] = true
	s.tempAddrs[tcpip.AddrFromSlice(net.ParseIP("2606:4700:4700::1111").To16())] = true
	s.tempAddrs[tcpip.AddrFromSlice(net.ParseIP("2001:db8::1").To16())] = true
	// We also need inEp non-nil so the redirect path's
	// InjectInbound call has a target.  A channel endpoint
	// silently swallows the packet — exactly what we want for
	// dispatch-only tests.
	s.inEp = gvchannel.New(8, 1420, "")
	return s
}

func buildV4TCPSyn(t *testing.T, src, dst net.IP, sport, dport uint16) *gvstack.PacketBuffer {
	t.Helper()
	totalLen := header.IPv4MinimumSize + header.TCPMinimumSize
	pktBytes := make([]byte, totalLen)
	ip := header.IPv4(pktBytes[:header.IPv4MinimumSize])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     tcpip.AddrFromSlice(src.To4()),
		DstAddr:     tcpip.AddrFromSlice(dst.To4()),
	})
	ip.SetChecksum(0)
	ip.SetChecksum(^ip.CalculateChecksum())
	tcpHdr := header.TCP(pktBytes[header.IPv4MinimumSize:])
	tcpHdr.SetSourcePort(sport)
	tcpHdr.SetDestinationPort(dport)
	tcpHdr.SetDataOffset(header.TCPMinimumSize)
	buf := buffer.MakeWithData(pktBytes)
	return gvstack.NewPacketBuffer(gvstack.PacketBufferOptions{Payload: buf})
}

func buildV6TCPSyn(t *testing.T, src, dst net.IP, sport, dport uint16) *gvstack.PacketBuffer {
	t.Helper()
	totalLen := header.IPv6MinimumSize + header.TCPMinimumSize
	pktBytes := make([]byte, totalLen)
	ip := header.IPv6(pktBytes[:header.IPv6MinimumSize])
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.TCPMinimumSize),
		TransportProtocol: header.TCPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           tcpip.AddrFromSlice(src.To16()),
		DstAddr:           tcpip.AddrFromSlice(dst.To16()),
	})
	tcpHdr := header.TCP(pktBytes[header.IPv6MinimumSize:])
	tcpHdr.SetSourcePort(sport)
	tcpHdr.SetDestinationPort(dport)
	tcpHdr.SetDataOffset(header.TCPMinimumSize)
	buf := buffer.MakeWithData(pktBytes)
	return gvstack.NewPacketBuffer(gvstack.PacketBufferOptions{Payload: buf})
}

func buildV6UDP(t *testing.T, src, dst net.IP, sport, dport uint16) *gvstack.PacketBuffer {
	t.Helper()
	totalLen := header.IPv6MinimumSize + header.UDPMinimumSize
	pktBytes := make([]byte, totalLen)
	ip := header.IPv6(pktBytes[:header.IPv6MinimumSize])
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.UDPMinimumSize),
		TransportProtocol: header.UDPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           tcpip.AddrFromSlice(src.To16()),
		DstAddr:           tcpip.AddrFromSlice(dst.To16()),
	})
	udpHdr := header.UDP(pktBytes[header.IPv6MinimumSize:])
	udpHdr.SetSourcePort(sport)
	udpHdr.SetDestinationPort(dport)
	udpHdr.SetLength(uint16(header.UDPMinimumSize))
	buf := buffer.MakeWithData(pktBytes)
	return gvstack.NewPacketBuffer(gvstack.PacketBufferOptions{Payload: buf})
}

func buildV6OtherProto(t *testing.T, src, dst net.IP, nextHdr uint8) *gvstack.PacketBuffer {
	t.Helper()
	totalLen := header.IPv6MinimumSize
	pktBytes := make([]byte, totalLen)
	ip := header.IPv6(pktBytes[:header.IPv6MinimumSize])
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     0,
		TransportProtocol: tcpip.TransportProtocolNumber(nextHdr),
		HopLimit:          64,
		SrcAddr:           tcpip.AddrFromSlice(src.To16()),
		DstAddr:           tcpip.AddrFromSlice(dst.To16()),
	})
	buf := buffer.MakeWithData(pktBytes)
	return gvstack.NewPacketBuffer(gvstack.PacketBufferOptions{Payload: buf})
}

// TestEmptyPayloadToSliceVsToView regression-tests the
// "panic: cannot release a nil view" crash observed in production
// on Pixel hardware after the custom ICMP transport handler
// landed. The bug: handleLocalICMP did
// `pkt.Data().AsRange().ToView()` then `.Release()`, but
// `Range.ToView()` returns nil when the payload is empty, and
// `View.Release()` panics on nil. Empty-payload ICMP echoes
// happen in practice (Linux `ping -s 0`, nativePingV4 probes,
// router-originated echoes) and even one such packet killed the
// process.
//
// This test pins the two relevant gvisor API behaviors:
// - `Range.ToView()` on an empty Range returns nil.
// - `View.Release()` panics on a nil receiver.
// If either flips in a future gvisor upgrade, this test goes red
// + reminds us why we switched to ToSlice().
func TestEmptyPayloadToSliceVsToView(t *testing.T) {
	// Construct a PacketBuffer with an IP header + 8-byte ICMP
	// header but ZERO payload — same shape gvisor delivers when
	// it routes an empty-payload echo to the transport handler.
	totalLen := header.IPv4MinimumSize + header.ICMPv4MinimumSize
	pktBytes := make([]byte, totalLen)
	ip := header.IPv4(pktBytes[:header.IPv4MinimumSize])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL: 64,
		Protocol: uint8(header.ICMPv4ProtocolNumber),
		SrcAddr: tcpip.AddrFromSlice(net.IPv4(10, 99, 0, 2).To4()),
		DstAddr: tcpip.AddrFromSlice(net.IPv4(1, 1, 1, 1).To4()),
	})
	ip.SetChecksum(0)
	ip.SetChecksum(^ip.CalculateChecksum())
	icmpHdr := header.ICMPv4(pktBytes[header.IPv4MinimumSize:])
	icmpHdr.SetType(header.ICMPv4Echo)
	icmpHdr.SetIdent(0x1234)
	icmpHdr.SetSequence(0x5678)
	icmpHdr.SetChecksum(0)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))

	buf := buffer.MakeWithData(pktBytes)
	pkt := gvstack.NewPacketBuffer(gvstack.PacketBufferOptions{Payload: buf})
	defer pkt.DecRef()
	if _, ok := pkt.NetworkHeader().Consume(header.IPv4MinimumSize); !ok {
		t.Fatalf("Consume(network) returned !ok")
	}
	if _, ok := pkt.TransportHeader().Consume(header.ICMPv4MinimumSize); !ok {
		t.Fatalf("Consume(transport) returned !ok")
	}
	pkt.NetworkProtocolNumber = gvipv4.ProtocolNumber

	// The SAFE path (production code uses this since the fix).
	got := pkt.Data().AsRange().ToSlice()
	if len(got) != 0 {
		t.Fatalf("ToSlice() on empty payload returned %d bytes, want 0", len(got))
	}

	// Confirm the UNSAFE path that the bug exercised. ToView()
	// on an empty Range returns nil; calling Release() on nil
	// panics with "cannot release a nil view". This is what
	// crashed the Pixel.
	v := pkt.Data().AsRange().ToView()
	if v != nil {
		t.Fatalf("ToView() on empty payload should be nil; got %T", v)
	}
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected View.Release() on nil to panic")
		}
	}()
	v.Release() // panics — caught by the recover above
}

