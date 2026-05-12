//go:build !android

package main

import (
	"encoding/binary"
	"net"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
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

func bytesNonZero(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
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
// This test pins the two relevant gvisor API behaviours:
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

