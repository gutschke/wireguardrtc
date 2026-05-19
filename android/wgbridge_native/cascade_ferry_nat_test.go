// Tests for the CASCADE-2 single-peer NAT translator.  Checksum
// correctness is the high-risk piece — incremental updates can
// silently produce a packet that "looks" fine but is rejected by
// the receiving stack.  Every test reconstructs the EXPECTED
// checksum from scratch via [computeInetChecksum] and asserts the
// translator produces the same value.

package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// ─── Internet-checksum reference implementation ─────────────────

// computeInetChecksum returns the one's-complement sum of the
// bytes (treated as 16-bit big-endian words) with the result then
// bit-flipped.  Used by tests to verify the translator's
// incremental update against a fresh-from-scratch checksum.
func computeInetChecksum(b []byte) uint16 {
	var acc uint32
	for i := 0; i+1 < len(b); i += 2 {
		acc += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		acc += uint32(b[len(b)-1]) << 8
	}
	for acc>>16 != 0 {
		acc = (acc & 0xffff) + (acc >> 16)
	}
	return ^uint16(acc)
}

// ─── Test fixtures ──────────────────────────────────────────────

func ipv4UDPPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	totalLen := 20 + 8 + len(payload)
	p := make([]byte, totalLen)
	// IP header.
	p[0] = 0x45                                    // version 4, IHL 5
	p[1] = 0                                       // TOS
	binary.BigEndian.PutUint16(p[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(p[4:6], 0x1234)     // identification
	p[6] = 0                                       // flags + frag offset
	p[7] = 0
	p[8] = 64                                      // TTL
	p[9] = 17                                      // protocol UDP
	binary.BigEndian.PutUint16(p[10:12], 0)        // checksum placeholder
	copy(p[12:16], srcIP[:])
	copy(p[16:20], dstIP[:])
	hdrCS := computeInetChecksum(p[:20])
	binary.BigEndian.PutUint16(p[10:12], hdrCS)
	// UDP header + payload.
	binary.BigEndian.PutUint16(p[20:22], srcPort)
	binary.BigEndian.PutUint16(p[22:24], dstPort)
	binary.BigEndian.PutUint16(p[24:26], uint16(8+len(payload)))
	binary.BigEndian.PutUint16(p[26:28], 0)        // checksum placeholder
	copy(p[28:], payload)
	// UDP pseudo-header + body checksum.
	pseudo := make([]byte, 12+8+len(payload))
	copy(pseudo[0:4], srcIP[:])
	copy(pseudo[4:8], dstIP[:])
	pseudo[8] = 0
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(8+len(payload)))
	copy(pseudo[12:], p[20:])
	udpCS := computeInetChecksum(pseudo)
	if udpCS == 0 {
		udpCS = 0xffff
	}
	binary.BigEndian.PutUint16(p[26:28], udpCS)
	return p
}

func ipv4TCPPacket(srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	tcpLen := 20 + len(payload)
	totalLen := 20 + tcpLen
	p := make([]byte, totalLen)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(totalLen))
	p[8] = 64
	p[9] = 6 // TCP
	copy(p[12:16], srcIP[:])
	copy(p[16:20], dstIP[:])
	hdrCS := computeInetChecksum(p[:20])
	binary.BigEndian.PutUint16(p[10:12], hdrCS)
	binary.BigEndian.PutUint16(p[20:22], srcPort)
	binary.BigEndian.PutUint16(p[22:24], dstPort)
	binary.BigEndian.PutUint32(p[24:28], 0x12345678) // seq
	binary.BigEndian.PutUint32(p[28:32], 0)          // ack
	p[32] = 0x50                                     // data offset = 5*4
	p[33] = 0x10                                     // ACK flag
	binary.BigEndian.PutUint16(p[34:36], 0xffff)     // window
	binary.BigEndian.PutUint16(p[36:38], 0)          // checksum placeholder
	binary.BigEndian.PutUint16(p[38:40], 0)          // urgent
	copy(p[40:], payload)
	// TCP pseudo-header + body checksum.
	pseudo := make([]byte, 12+tcpLen)
	copy(pseudo[0:4], srcIP[:])
	copy(pseudo[4:8], dstIP[:])
	pseudo[8] = 0
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(tcpLen))
	copy(pseudo[12:], p[20:])
	tcpCS := computeInetChecksum(pseudo)
	binary.BigEndian.PutUint16(p[36:38], tcpCS)
	return p
}

func ipv6UDPPacket(srcIP, dstIP [16]byte, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	totalLen := 40 + udpLen
	p := make([]byte, totalLen)
	p[0] = 0x60                                    // version 6
	binary.BigEndian.PutUint16(p[4:6], uint16(udpLen))
	p[6] = 17                                      // next header UDP
	p[7] = 64                                      // hop limit
	copy(p[8:24], srcIP[:])
	copy(p[24:40], dstIP[:])
	binary.BigEndian.PutUint16(p[40:42], srcPort)
	binary.BigEndian.PutUint16(p[42:44], dstPort)
	binary.BigEndian.PutUint16(p[44:46], uint16(udpLen))
	binary.BigEndian.PutUint16(p[46:48], 0)        // checksum placeholder
	copy(p[48:], payload)
	// IPv6 pseudo-header (RFC 8200 §8.1) + body checksum.
	pseudo := make([]byte, 40+udpLen)
	copy(pseudo[0:16], srcIP[:])
	copy(pseudo[16:32], dstIP[:])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(udpLen))
	pseudo[36] = 0
	pseudo[37] = 0
	pseudo[38] = 0
	pseudo[39] = 17
	copy(pseudo[40:], p[40:])
	cs := computeInetChecksum(pseudo)
	if cs == 0 {
		cs = 0xffff
	}
	binary.BigEndian.PutUint16(p[46:48], cs)
	return p
}

// ─── Disabled / no-op paths ─────────────────────────────────────

func TestNatTable_DisabledPassesThrough(t *testing.T) {
	// No joiner-own addresses configured → translator must be a
	// pure no-op on any input.
	n := newNatTable(netip.Addr{}, netip.Addr{})
	src := [4]byte{10, 0, 0, 5}
	dst := [4]byte{1, 2, 3, 4}
	original := ipv4UDPPacket(src, dst, 1024, 53, []byte("query"))
	pkt := append([]byte{}, original...)
	if n.snatForward(pkt) {
		t.Fatal("snatForward should be no-op with disabled NAT")
	}
	if !bytesEqual(pkt, original) {
		t.Fatal("packet was mutated despite disabled NAT")
	}
	if n.snatReverse(pkt) {
		t.Fatal("snatReverse should be no-op with disabled NAT")
	}
}

func TestNatTable_InvalidPacketsPassThrough(t *testing.T) {
	n := newNatTable(netip.MustParseAddr("10.99.0.99"), netip.Addr{})
	// Empty.
	if n.snatForward(nil) {
		t.Error("nil packet must not be mutated")
	}
	// Garbage version nibble.
	garbage := []byte{0xf0, 0, 0, 0}
	if n.snatForward(garbage) {
		t.Error("non-v4/v6 version must not be mutated")
	}
	// Too short for IPv4.
	short := []byte{0x45, 0, 0, 1}
	if n.snatForward(short) {
		t.Error("truncated IPv4 must not be mutated")
	}
}

// ─── IPv4 forward + reverse ─────────────────────────────────────

func TestNatTable_V4ForwardUDPRewritesSrcAndChecksums(t *testing.T) {
	joinerOwn := netip.MustParseAddr("10.99.0.99")
	n := newNatTable(joinerOwn, netip.Addr{})
	origSrc := [4]byte{10, 50, 0, 7}
	dst := [4]byte{1, 1, 1, 1}
	pkt := ipv4UDPPacket(origSrc, dst, 12345, 53, []byte("hello"))

	if !n.snatForward(pkt) {
		t.Fatal("snatForward returned false; expected mutation")
	}

	// Src should now be joiner-own.
	gotSrc := [4]byte{pkt[12], pkt[13], pkt[14], pkt[15]}
	want := joinerOwn.As4()
	if gotSrc != want {
		t.Errorf("src not rewritten: got %v want %v", gotSrc, want)
	}
	// Verify checksums against a fresh-from-scratch build.
	expected := ipv4UDPPacket(want, dst, 12345, 53, []byte("hello"))
	if !bytesEqual(pkt, expected) {
		t.Errorf("post-translation packet differs from fresh-build expected:\n got %x\nwant %x", pkt, expected)
	}
	// Last-seen src should be recorded for the reverse path.
	if n.lastSrcV4 != netip.AddrFrom4(origSrc) {
		t.Errorf("lastSrcV4 = %v, want %v", n.lastSrcV4, origSrc)
	}
}

func TestNatTable_V4ReverseUDPRestoresDstAndChecksums(t *testing.T) {
	joinerOwn := netip.MustParseAddr("10.99.0.99")
	n := newNatTable(joinerOwn, netip.Addr{})
	origSrc := [4]byte{10, 50, 0, 7}
	dst := [4]byte{1, 1, 1, 1}

	// Forward first to seed the lastSrc memory.
	fwd := ipv4UDPPacket(origSrc, dst, 12345, 53, []byte("hello"))
	if !n.snatForward(fwd) {
		t.Fatal("forward should mutate")
	}

	// Reverse direction: server replied; dst is joiner-own, body
	// is a UDP response.  Translator should rewrite dst back to
	// origSrc and fix checksums.
	joinerOwnBytes := joinerOwn.As4()
	rev := ipv4UDPPacket(dst, joinerOwnBytes, 53, 12345, []byte("reply"))
	if !n.snatReverse(rev) {
		t.Fatal("reverse returned false")
	}
	gotDst := [4]byte{rev[16], rev[17], rev[18], rev[19]}
	if gotDst != origSrc {
		t.Errorf("dst not restored: got %v want %v", gotDst, origSrc)
	}
	expected := ipv4UDPPacket(dst, origSrc, 53, 12345, []byte("reply"))
	if !bytesEqual(rev, expected) {
		t.Errorf("reverse packet differs:\n got %x\nwant %x", rev, expected)
	}
}

func TestNatTable_V4ForwardTCPChecksumsCorrect(t *testing.T) {
	joinerOwn := netip.MustParseAddr("10.99.0.99")
	n := newNatTable(joinerOwn, netip.Addr{})
	origSrc := [4]byte{10, 50, 0, 7}
	dst := [4]byte{1, 1, 1, 1}
	pkt := ipv4TCPPacket(origSrc, dst, 5555, 22, []byte("ssh data"))

	if !n.snatForward(pkt) {
		t.Fatal("expected mutation")
	}
	want := ipv4TCPPacket(joinerOwn.As4(), dst, 5555, 22, []byte("ssh data"))
	if !bytesEqual(pkt, want) {
		t.Errorf("TCP forward packet differs:\n got %x\nwant %x", pkt, want)
	}
}

func TestNatTable_V4ReverseSkipsWhenNoLastSrc(t *testing.T) {
	// Reverse without a preceding forward: nothing to translate to.
	joinerOwn := netip.MustParseAddr("10.99.0.99")
	n := newNatTable(joinerOwn, netip.Addr{})
	dst := [4]byte{1, 1, 1, 1}
	pkt := ipv4UDPPacket(dst, joinerOwn.As4(), 53, 12345, []byte("orphan"))
	original := append([]byte{}, pkt...)
	if n.snatReverse(pkt) {
		t.Error("reverse without prior forward should not mutate")
	}
	if !bytesEqual(pkt, original) {
		t.Error("packet was mutated despite no last-src memory")
	}
}

func TestNatTable_V4SkipsWhenSrcAlreadyJoinerOwn(t *testing.T) {
	// Defensive: a packet whose src is already the joiner-own
	// address must not be rewritten (would set lastSrc = joinerOwn
	// and break the reverse path).
	joinerOwn := netip.MustParseAddr("10.99.0.99")
	n := newNatTable(joinerOwn, netip.Addr{})
	pkt := ipv4UDPPacket(joinerOwn.As4(), [4]byte{1, 1, 1, 1}, 1024, 53, []byte("x"))
	if n.snatForward(pkt) {
		t.Error("packet sourced from joiner-own should not be translated")
	}
}

// ─── IPv6 forward + reverse ─────────────────────────────────────

func TestNatTable_V6ForwardUDPRewritesSrcAndChecksums(t *testing.T) {
	joinerOwn := netip.MustParseAddr("2001:db8:abcd::3")
	n := newNatTable(netip.Addr{}, joinerOwn)
	origSrc := mustAddr16("fd99:1234::5")
	dst := mustAddr16("2001:4860:4860::8888")
	pkt := ipv6UDPPacket(origSrc, dst, 12345, 53, []byte("hello6"))

	if !n.snatForward(pkt) {
		t.Fatal("expected mutation")
	}
	want := ipv6UDPPacket(joinerOwn.As16(), dst, 12345, 53, []byte("hello6"))
	if !bytesEqual(pkt, want) {
		t.Errorf("v6 forward packet differs:\n got %x\nwant %x", pkt, want)
	}
	if n.lastSrcV6 != netip.AddrFrom16(origSrc) {
		t.Errorf("lastSrcV6 = %v, want %v", n.lastSrcV6, origSrc)
	}
}

func TestNatTable_V6ReverseUDPRestoresDstAndChecksums(t *testing.T) {
	joinerOwn := netip.MustParseAddr("2001:db8:abcd::3")
	n := newNatTable(netip.Addr{}, joinerOwn)
	origSrc := mustAddr16("fd99:1234::5")
	dst := mustAddr16("2001:4860:4860::8888")

	fwd := ipv6UDPPacket(origSrc, dst, 12345, 53, []byte("hello6"))
	if !n.snatForward(fwd) {
		t.Fatal("forward should mutate")
	}
	rev := ipv6UDPPacket(dst, joinerOwn.As16(), 53, 12345, []byte("reply6"))
	if !n.snatReverse(rev) {
		t.Fatal("reverse returned false")
	}
	want := ipv6UDPPacket(dst, origSrc, 53, 12345, []byte("reply6"))
	if !bytesEqual(rev, want) {
		t.Errorf("v6 reverse packet differs:\n got %x\nwant %x", rev, want)
	}
}

// ipv6ICMPv6EchoPacket builds an ICMPv6 echo request.  Unlike
// IPv4 ICMP, ICMPv6's checksum covers the IPv6 pseudo-header
// (RFC 4443 §2.3), so address changes must invalidate it and
// the NAT must recompute.
func ipv6ICMPv6EchoPacket(srcIP, dstIP [16]byte, ident, seq uint16, payload []byte) []byte {
	icmpLen := 8 + len(payload)
	totalLen := 40 + icmpLen
	p := make([]byte, totalLen)
	p[0] = 0x60                                    // version 6
	binary.BigEndian.PutUint16(p[4:6], uint16(icmpLen))
	p[6] = 58                                      // next header ICMPv6
	p[7] = 64                                      // hop limit
	copy(p[8:24], srcIP[:])
	copy(p[24:40], dstIP[:])
	// ICMPv6 echo request: type 128, code 0.
	p[40] = 128
	p[41] = 0
	binary.BigEndian.PutUint16(p[42:44], 0)        // checksum placeholder
	binary.BigEndian.PutUint16(p[44:46], ident)
	binary.BigEndian.PutUint16(p[46:48], seq)
	copy(p[48:], payload)
	// Pseudo-header + ICMPv6 body checksum.
	pseudo := make([]byte, 40+icmpLen)
	copy(pseudo[0:16], srcIP[:])
	copy(pseudo[16:32], dstIP[:])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(icmpLen))
	pseudo[36] = 0
	pseudo[37] = 0
	pseudo[38] = 0
	pseudo[39] = 58
	copy(pseudo[40:], p[40:])
	cs := computeInetChecksum(pseudo)
	binary.BigEndian.PutUint16(p[42:44], cs)
	return p
}

func TestNatTable_V6ForwardICMPv6ChecksumsCorrect(t *testing.T) {
	// Critic round 1 flagged ICMPv6 as the most likely first-packet
	// on any new path (NDP / PMTU / echo) and noted it has no
	// dedicated test — v4 ICMP is checksum-only-over-body so we
	// can skip it, but ICMPv6 includes the pseudo-header per
	// RFC 4443 §2.3 and absolutely must be recomputed.
	joinerOwn := netip.MustParseAddr("2001:db8:abcd::3")
	n := newNatTable(netip.Addr{}, joinerOwn)
	origSrc := mustAddr16("fd99:1234::5")
	dst := mustAddr16("2606:4700:4700::1111")
	pkt := ipv6ICMPv6EchoPacket(origSrc, dst, 0xbeef, 1, []byte("ping6"))
	if !n.snatForward(pkt) {
		t.Fatal("expected mutation")
	}
	want := ipv6ICMPv6EchoPacket(joinerOwn.As16(), dst, 0xbeef, 1, []byte("ping6"))
	if !bytesEqual(pkt, want) {
		t.Errorf("ICMPv6 forward packet differs:\n got %x\nwant %x", pkt, want)
	}
}

func TestNatTable_V6ReverseICMPv6ChecksumsCorrect(t *testing.T) {
	joinerOwn := netip.MustParseAddr("2001:db8:abcd::3")
	n := newNatTable(netip.Addr{}, joinerOwn)
	origSrc := mustAddr16("fd99:1234::5")
	dst := mustAddr16("2606:4700:4700::1111")
	// Seed lastSrc via a forward.
	fwd := ipv6ICMPv6EchoPacket(origSrc, dst, 0xbeef, 1, []byte("ping6"))
	if !n.snatForward(fwd) {
		t.Fatal("forward should mutate")
	}
	// Reply: src/dst swapped, type=129 (echo reply).
	rev := ipv6ICMPv6EchoPacket(dst, joinerOwn.As16(), 0xbeef, 1, []byte("pong6"))
	rev[40] = 129 // echo reply
	// Recompute its checksum after the type change.
	rev[42], rev[43] = 0, 0
	joinerOwnBytes := joinerOwn.As16()
	pseudo := make([]byte, 40+len(rev)-40)
	copy(pseudo[0:16], dst[:])
	copy(pseudo[16:32], joinerOwnBytes[:])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(rev)-40))
	pseudo[39] = 58
	copy(pseudo[40:], rev[40:])
	cs := computeInetChecksum(pseudo)
	binary.BigEndian.PutUint16(rev[42:44], cs)

	if !n.snatReverse(rev) {
		t.Fatal("reverse returned false")
	}
	// Expected post-translation packet: built fresh with the
	// origSrc dst.
	want := ipv6ICMPv6EchoPacket(dst, origSrc, 0xbeef, 1, []byte("pong6"))
	want[40] = 129
	want[42], want[43] = 0, 0
	pseudo2 := make([]byte, 40+len(want)-40)
	copy(pseudo2[0:16], dst[:])
	copy(pseudo2[16:32], origSrc[:])
	binary.BigEndian.PutUint32(pseudo2[32:36], uint32(len(want)-40))
	pseudo2[39] = 58
	copy(pseudo2[40:], want[40:])
	wantCS := computeInetChecksum(pseudo2)
	binary.BigEndian.PutUint16(want[42:44], wantCS)
	if !bytesEqual(rev, want) {
		t.Errorf("ICMPv6 reverse packet differs:\n got %x\nwant %x", rev, want)
	}
}

// TestNatTable_V6SetJoinerAddrsPreservesLastSrc — the round-1
// critic's sev-4: a mid-flight setJoinerAddrs call must NOT
// clobber the lastSrc memory, or the reverse path of an in-flight
// flow breaks the instant the joiner re-publishes its address.
func TestNatTable_V6SetJoinerAddrsPreservesLastSrc(t *testing.T) {
	joinerOwn := netip.MustParseAddr("2001:db8:abcd::3")
	n := newNatTable(netip.Addr{}, joinerOwn)
	origSrc := mustAddr16("fd99:1234::5")
	dst := mustAddr16("2606:4700:4700::1111")
	fwd := ipv6ICMPv6EchoPacket(origSrc, dst, 0xbeef, 1, []byte("p"))
	if !n.snatForward(fwd) {
		t.Fatal("forward should mutate")
	}
	// Re-publish the same joiner-own address.  Reverse path must
	// still find lastSrcV6.
	n.setJoinerAddrs(netip.Addr{}, joinerOwn)
	rev := ipv6ICMPv6EchoPacket(dst, joinerOwn.As16(), 0xbeef, 1, []byte("q"))
	if !n.snatReverse(rev) {
		t.Fatal("reverse should still mutate after re-publish")
	}
	gotDst := [16]byte{}
	copy(gotDst[:], rev[24:40])
	if gotDst != origSrc {
		t.Errorf("dst not restored: got %v want %v", gotDst, origSrc)
	}
}

func TestNatTable_V6OnlyWhenFamilyEnabled(t *testing.T) {
	// v4 enabled, v6 disabled → v6 packets pass through.
	n := newNatTable(netip.MustParseAddr("10.99.0.99"), netip.Addr{})
	origSrc := mustAddr16("fd99:1234::5")
	dst := mustAddr16("2001:4860:4860::8888")
	pkt := ipv6UDPPacket(origSrc, dst, 12345, 53, []byte("nope"))
	original := append([]byte{}, pkt...)
	if n.snatForward(pkt) {
		t.Error("v6 packet must pass through when v6 NAT is disabled")
	}
	if !bytesEqual(pkt, original) {
		t.Error("v6 packet mutated despite disabled v6 NAT")
	}
}

func TestNatTable_RejectsWrongFamilyAddresses(t *testing.T) {
	// Defensive constructor input: a v6 address in the v4 slot
	// gets zero'd, not panic.
	n := newNatTable(netip.MustParseAddr("2001::1"), netip.MustParseAddr("10.0.0.1"))
	if n.enabledV4() {
		t.Error("constructor accepted v6 address as v4")
	}
	if n.enabledV6() {
		t.Error("constructor accepted v4 address as v6")
	}
}

// ─── Checksum helper sanity ─────────────────────────────────────

func TestIncrementalChecksumUpdate_MatchesFromScratch(t *testing.T) {
	// Compose a synthetic 32-byte buffer, compute its checksum,
	// mutate a 4-byte region, apply incremental update, and check
	// against from-scratch.
	buf := make([]byte, 32)
	for i := range buf {
		buf[i] = byte(0xa0 ^ i)
	}
	original := append([]byte{}, buf...)
	csOrig := computeInetChecksum(buf)
	// Mutate bytes 12..15.
	newSlice := []byte{0x01, 0x02, 0x03, 0x04}
	copy(buf[12:16], newSlice)
	csFromScratch := computeInetChecksum(buf)
	csIncremental := incrementalChecksumUpdate(csOrig, original[12:16], newSlice)
	if csFromScratch != csIncremental {
		t.Errorf("incremental %#x != from-scratch %#x", csIncremental, csFromScratch)
	}
}

// TestSumOnesComplement_PanicsOnOddLength pins the loud-failure
// contract: callers that pass odd-length slices to the incremental
// update helper get a panic rather than a silently-wrong checksum.
// The NAT use case always passes 4-byte or 16-byte address
// regions, so production never trips this — the test exists to
// catch a future caller that accidentally violates the contract.
func TestSumOnesComplement_PanicsOnOddLength(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on odd-length input, got none")
		}
	}()
	_ = sumOnesComplement([]byte{0x12, 0x34, 0x56}, false)
}

// TestIncrementalChecksumUpdate_DefendsAgainstAddressLenChange
// pins the IPv6-shape case: a 16-byte address change must produce
// the same checksum as a from-scratch recompute over the modified
// buffer.  16-byte regions are the largest the NAT use case
// touches.
func TestIncrementalChecksumUpdate_DefendsAgainstAddressLenChange(t *testing.T) {
	// Construct a 40-byte synthetic v6-style header where the
	// last 32 bytes are "addresses".
	buf := make([]byte, 40)
	for i := range buf {
		buf[i] = byte(i * 7)
	}
	original := append([]byte{}, buf...)
	csOrig := computeInetChecksum(buf)
	// Replace bytes 24..39 (a 16-byte v6 dst-like region).
	newDst := make([]byte, 16)
	for i := range newDst {
		newDst[i] = byte(0x42 ^ i)
	}
	copy(buf[24:40], newDst)
	csFromScratch := computeInetChecksum(buf)
	csIncremental := incrementalChecksumUpdate(csOrig, original[24:40], newDst)
	if csFromScratch != csIncremental {
		t.Errorf("v6-size incremental %#x != from-scratch %#x", csIncremental, csFromScratch)
	}
}

// ─── Round-2 critic tests ──────────────────────────────────────
//
// Cover the v6 "unknown next-header → undo SNAT" branch, the v6
// non-first-fragment path that must preserve the rewrite but
// skip the transport checksum, and the bounded-hop ext-hdr walker.

// ipv6UnknownNHPacket builds an IPv6 packet whose next-header is
// the caller-supplied protocol byte (typically 50=ESP or 51=AH).
// The "transport" payload is opaque bytes — we never parse it.
func ipv6UnknownNHPacket(srcIP, dstIP [16]byte, nextHdr byte, payload []byte) []byte {
	totalLen := 40 + len(payload)
	p := make([]byte, totalLen)
	p[0] = 0x60                                    // version 6
	binary.BigEndian.PutUint16(p[4:6], uint16(len(payload)))
	p[6] = nextHdr
	p[7] = 64                                      // hop limit
	copy(p[8:24], srcIP[:])
	copy(p[24:40], dstIP[:])
	copy(p[40:], payload)
	return p
}

func TestNatTable_V6ForwardESPLeavesPacketUntouched(t *testing.T) {
	// Critic round 2 sev-2: AH/ESP undo branch had no test.
	// Verify that an ESP packet (next-header 50) goes through
	// snatForward returning false AND the packet bytes are
	// bitwise identical to input — no partial mutation.
	joinerOwn := netip.MustParseAddr("2001:db8:abcd::3")
	n := newNatTable(netip.Addr{}, joinerOwn)
	origSrc := mustAddr16("fd99:1234::5")
	dst := mustAddr16("2606:4700:4700::1111")
	body := []byte("opaque ESP body bytes — never decoded by NAT")
	pkt := ipv6UnknownNHPacket(origSrc, dst, 50 /* ESP */, body)
	original := make([]byte, len(pkt))
	copy(original, pkt)

	if n.snatForward(pkt) {
		t.Fatal("ESP packet must NOT be marked as mutated")
	}
	if !bytesEqual(pkt, original) {
		t.Errorf("ESP packet was partially mutated:\n got %x\nwant %x", pkt, original)
	}
	// lastSrcV6 must NOT be seeded — a refused SNAT must not leak
	// the original source into the reverse-direction memory, or
	// later reply traffic will misroute.
	if n.lastSrcV6.IsValid() {
		t.Errorf("refused-ESP SNAT must not seed lastSrcV6, got %v", n.lastSrcV6)
	}
}

func TestNatTable_V6ForwardAHLeavesPacketUntouched(t *testing.T) {
	// Same as ESP but next-header = 51 (AH).
	joinerOwn := netip.MustParseAddr("2001:db8:abcd::3")
	n := newNatTable(netip.Addr{}, joinerOwn)
	origSrc := mustAddr16("fd99:1234::5")
	dst := mustAddr16("2606:4700:4700::1111")
	body := []byte("opaque AH body bytes")
	pkt := ipv6UnknownNHPacket(origSrc, dst, 51 /* AH */, body)
	original := make([]byte, len(pkt))
	copy(original, pkt)

	if n.snatForward(pkt) {
		t.Fatal("AH packet must NOT be marked as mutated")
	}
	if !bytesEqual(pkt, original) {
		t.Errorf("AH packet was partially mutated:\n got %x\nwant %x", pkt, original)
	}
	if n.lastSrcV6.IsValid() {
		t.Errorf("refused-AH SNAT must not seed lastSrcV6, got %v", n.lastSrcV6)
	}
}

func TestNatTable_V6ReverseESPLeavesPacketUntouched(t *testing.T) {
	// Reverse direction: a packet destined for joinerOwnV6 whose
	// next-header is ESP must undo the DNAT just like forward.
	joinerOwn := netip.MustParseAddr("2001:db8:abcd::3")
	n := newNatTable(netip.Addr{}, joinerOwn)
	// Seed lastSrcV6 via a UDP forward first.
	origSrc := mustAddr16("fd99:1234::5")
	dst := mustAddr16("2606:4700:4700::1111")
	fwd := ipv6UDPPacket(origSrc, dst, 12345, 53, []byte("seed"))
	if !n.snatForward(fwd) {
		t.Fatal("UDP forward should mutate (seeding lastSrcV6)")
	}
	// Now build an ESP reply to joinerOwn — must be refused
	// without mutating bytes.
	espRev := ipv6UnknownNHPacket(dst, joinerOwn.As16(), 50, []byte("esp-reply"))
	original := make([]byte, len(espRev))
	copy(original, espRev)
	if n.snatReverse(espRev) {
		t.Fatal("ESP reverse must NOT mutate")
	}
	if !bytesEqual(espRev, original) {
		t.Errorf("ESP reverse partially mutated:\n got %x\nwant %x", espRev, original)
	}
}

// ipv6FragmentedUDPPacket builds an IPv6 packet whose chain is
// IPv6 → Fragment(NH=UDP) → ... where ... is either an actual UDP
// header (for first fragment, fragOffset=0) or opaque payload bytes
// (for non-first fragments, fragOffset!=0).
func ipv6FragmentedUDPPacket(
	srcIP, dstIP [16]byte,
	fragOffsetUnits uint16, moreFragments bool,
	body []byte,
) []byte {
	payloadLen := 8 + len(body) // 8-byte fragment header + body
	totalLen := 40 + payloadLen
	p := make([]byte, totalLen)
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:6], uint16(payloadLen))
	p[6] = 44                                      // next-hdr = Fragment
	p[7] = 64
	copy(p[8:24], srcIP[:])
	copy(p[24:40], dstIP[:])
	// Fragment header (RFC 8200 §4.5).
	p[40] = 17                                     // next-hdr = UDP
	p[41] = 0                                      // reserved
	fragWord := fragOffsetUnits << 3
	if moreFragments {
		fragWord |= 1
	}
	binary.BigEndian.PutUint16(p[42:44], fragWord)
	binary.BigEndian.PutUint32(p[44:48], 0xdeadbeef) // identification
	// Body
	copy(p[48:], body)
	return p
}

func TestNatTable_V6ForwardNonFirstFragmentRewritesAddrSkipsChecksum(t *testing.T) {
	// Critic round 2 sev-2: non-first fragments have NO transport
	// header at the walker's `off` — the bytes there are payload.
	// Verify (a) source address is rewritten, (b) payload bytes
	// at the would-be-checksum offset are NOT corrupted.
	joinerOwn := netip.MustParseAddr("2001:db8:abcd::3")
	n := newNatTable(netip.Addr{}, joinerOwn)
	origSrc := mustAddr16("fd99:1234::5")
	dst := mustAddr16("2606:4700:4700::1111")
	// Body has distinctive bytes at the offset where the walker
	// would otherwise read a UDP checksum (off+6) so we can spot
	// corruption.
	body := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	pkt := ipv6FragmentedUDPPacket(origSrc, dst, 1 /* non-zero offset */, false, body)
	bodyBeforeNAT := make([]byte, len(body))
	copy(bodyBeforeNAT, pkt[48:])

	if !n.snatForward(pkt) {
		t.Fatal("non-first fragment must still have its src rewritten")
	}
	// Source MUST be rewritten.
	var gotSrc [16]byte
	copy(gotSrc[:], pkt[8:24])
	if gotSrc != joinerOwn.As16() {
		t.Errorf("src not rewritten: got %x want %x", gotSrc, joinerOwn.As16())
	}
	// Body bytes MUST be unchanged — the walker's would-be
	// checksum offset on this packet was somewhere inside the
	// payload, NOT a real UDP checksum field.
	if !bytesEqual(pkt[48:], bodyBeforeNAT) {
		t.Errorf("non-first fragment payload corrupted:\n got %x\nwant %x",
			pkt[48:], bodyBeforeNAT)
	}
}

func TestNatTable_V6ForwardFirstFragmentRewritesChecksum(t *testing.T) {
	// First fragment (offset=0) DOES carry the transport header
	// at the walker's `off`.  Verify the checksum still gets
	// updated correctly, distinct from the non-first-fragment
	// payload-preservation case.
	joinerOwn := netip.MustParseAddr("2001:db8:abcd::3")
	n := newNatTable(netip.Addr{}, joinerOwn)
	origSrc := mustAddr16("fd99:1234::5")
	dst := mustAddr16("2606:4700:4700::1111")
	// Construct a "first fragment" carrying a valid UDP header.
	// We compute the checksum against the ORIGINAL src for the
	// reassembled datagram, then expect the NAT to update it to
	// match the joiner-own src.
	udpBody := []byte("first-fragment-payload")
	udpLen := 8 + len(udpBody)
	udpHdrAndBody := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udpHdrAndBody[0:2], 12345)
	binary.BigEndian.PutUint16(udpHdrAndBody[2:4], 53)
	binary.BigEndian.PutUint16(udpHdrAndBody[4:6], uint16(udpLen))
	binary.BigEndian.PutUint16(udpHdrAndBody[6:8], 0)
	copy(udpHdrAndBody[8:], udpBody)
	pseudo := make([]byte, 40+udpLen)
	copy(pseudo[0:16], origSrc[:])
	copy(pseudo[16:32], dst[:])
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(udpLen))
	pseudo[39] = 17
	copy(pseudo[40:], udpHdrAndBody)
	udpCS := computeInetChecksum(pseudo)
	if udpCS == 0 {
		udpCS = 0xffff
	}
	binary.BigEndian.PutUint16(udpHdrAndBody[6:8], udpCS)

	pkt := ipv6FragmentedUDPPacket(origSrc, dst, 0 /* first fragment */, true, udpHdrAndBody)

	if !n.snatForward(pkt) {
		t.Fatal("first fragment must be mutated")
	}
	// Verify the UDP checksum now matches the joiner-own
	// pseudo-header.
	wantUDPHdrAndBody := make([]byte, len(udpHdrAndBody))
	copy(wantUDPHdrAndBody, udpHdrAndBody)
	binary.BigEndian.PutUint16(wantUDPHdrAndBody[6:8], 0)
	pseudo2 := make([]byte, 40+udpLen)
	joinerOwnBytes := joinerOwn.As16()
	copy(pseudo2[0:16], joinerOwnBytes[:])
	copy(pseudo2[16:32], dst[:])
	binary.BigEndian.PutUint32(pseudo2[32:36], uint32(udpLen))
	pseudo2[39] = 17
	copy(pseudo2[40:], wantUDPHdrAndBody)
	wantCS := computeInetChecksum(pseudo2)
	if wantCS == 0 {
		wantCS = 0xffff
	}
	gotCS := binary.BigEndian.Uint16(pkt[48+6 : 48+8])
	if gotCS != wantCS {
		t.Errorf("first-fragment UDP checksum: got %#x want %#x", gotCS, wantCS)
	}
}

func TestWalkV6ExtensionHeaders_BoundedHopCount(t *testing.T) {
	// Critic round 2 sev-2: an unbounded walker can be exploited
	// by a malformed packet chained as DstOpts→DstOpts→... ad
	// infinitum.  Verify the v6ExtHdrMaxHops cap kicks in and
	// returns v6WalkParseFailure rather than spinning forever.
	// Build a chain of 16 zero-length DestOpts headers (each
	// extLen=8 bytes via HdrExtLen=0).
	chainCount := 16
	totalLen := 40 + chainCount*8
	p := make([]byte, totalLen)
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:6], uint16(chainCount*8))
	p[6] = 60 // DestOpts as first ext-hdr
	p[7] = 64
	// Each ext-hdr: NextHeader=60 (DestOpts again), HdrExtLen=0.
	for i := 0; i < chainCount-1; i++ {
		base := 40 + i*8
		p[base] = 60   // chain to another DestOpts
		p[base+1] = 0  // HdrExtLen=0 → 8 bytes total
	}
	// Final ext-hdr: chain to UDP (17) — but we should never
	// reach this because the cap fires first.
	final := 40 + (chainCount-1)*8
	p[final] = 17
	p[final+1] = 0

	_, _, action := walkV6ExtensionHeaders(p)
	if action != v6WalkParseFailure {
		t.Errorf("expected v6WalkParseFailure on 16-deep DestOpts chain, got action=%v",
			action)
	}
}

func TestNatTable_V6ForwardDeepExtHdrChainUndoesSNAT(t *testing.T) {
	// End-to-end: snatForward on a pathologically deep ext-hdr
	// chain must undo the SNAT (the walker returns parse failure,
	// fixupV6 returns false, snatV6 reverts the address rewrite).
	joinerOwn := netip.MustParseAddr("2001:db8:abcd::3")
	n := newNatTable(netip.Addr{}, joinerOwn)
	origSrc := mustAddr16("fd99:1234::5")
	dst := mustAddr16("2606:4700:4700::1111")

	chainCount := 16
	totalLen := 40 + chainCount*8
	p := make([]byte, totalLen)
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:6], uint16(chainCount*8))
	p[6] = 60
	p[7] = 64
	copy(p[8:24], origSrc[:])
	copy(p[24:40], dst[:])
	for i := 0; i < chainCount-1; i++ {
		base := 40 + i*8
		p[base] = 60
		p[base+1] = 0
	}
	final := 40 + (chainCount-1)*8
	p[final] = 17
	p[final+1] = 0

	original := make([]byte, len(p))
	copy(original, p)

	if n.snatForward(p) {
		t.Fatal("deep ext-hdr chain must result in no mutation")
	}
	if !bytesEqual(p, original) {
		t.Errorf("deep ext-hdr chain partially mutated:\n got %x\nwant %x", p, original)
	}
	if n.lastSrcV6.IsValid() {
		t.Errorf("refused deep-chain SNAT must not seed lastSrcV6")
	}
}

func TestNatTable_V6MulticastDstPassesThrough(t *testing.T) {
	// Critic round 3 sev-3: multicast (ff00::/8) carries MLD
	// reports and link-local control traffic that must not be
	// SNAT'd.
	joinerOwn := netip.MustParseAddr("2001:db8:abcd::3")
	n := newNatTable(netip.Addr{}, joinerOwn)
	src := mustAddr16("fd99:1234::5")
	allRouters := mustAddr16("ff02::2")
	pkt := ipv6UDPPacket(src, allRouters, 12345, 53, []byte("multicast"))
	original := make([]byte, len(pkt))
	copy(original, pkt)

	if n.snatForward(pkt) {
		t.Fatal("multicast dst must NOT be mutated")
	}
	if !bytesEqual(pkt, original) {
		t.Errorf("multicast packet partially mutated:\n got %x\nwant %x", pkt, original)
	}
}

func TestNatTable_V6LinkLocalSrcPassesThrough(t *testing.T) {
	// Critic round 2 sev-3: NDP / link-local must NOT be SNAT'd.
	// A packet with fe80::/10 src should pass through unchanged.
	joinerOwn := netip.MustParseAddr("2001:db8:abcd::3")
	n := newNatTable(netip.Addr{}, joinerOwn)
	linkLocalSrc := mustAddr16("fe80::1")
	dst := mustAddr16("2606:4700:4700::1111")
	pkt := ipv6UDPPacket(linkLocalSrc, dst, 12345, 53, []byte("link-local"))
	original := make([]byte, len(pkt))
	copy(original, pkt)

	if n.snatForward(pkt) {
		t.Fatal("link-local src must NOT be mutated")
	}
	if !bytesEqual(pkt, original) {
		t.Errorf("link-local packet partially mutated:\n got %x\nwant %x", pkt, original)
	}
}

// ─── helpers ────────────────────────────────────────────────────

func mustAddr16(s string) [16]byte {
	return netip.MustParseAddr(s).As16()
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
