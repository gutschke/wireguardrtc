// CASCADE-2 NAT: single-peer source-address translation between the
// host and joiner stacks.
//
// Commercial WireGuard providers (Mullvad, NordVPN, IVPN, etc.) hand
// out a single /32 + /128 per peer and won't widen the per-peer
// AllowedIPs server-side.  Without NAT, cascade packets carry the
// host-tunnel client's inner source address, which doesn't match the
// joiner's allowed-ips on the upstream and gets silently dropped.
//
// This translator rewrites the source on the host→joiner direction
// to the joiner's own assigned address (the wg-quick `[Interface]
// Address` line).  On the reverse direction (joiner→host), packets
// destined for the joiner-own address get translated back to the
// last-seen original source.
//
// MVP scope: single-peer behind the host tunnel, no port
// translation.  The state is a single "last-seen source" entry per
// IP family.  Multi-peer support (= PAT-style port translation +
// conntrack table) is a follow-up.
//
// Why not gvisor's iptables MASQUERADE: simpler, fully testable in
// isolation, and the ferry's drain loops already own the packet
// boundary.  The conntrack-equivalent (mapping reverse traffic
// back) reduces to a single entry per family for the single-peer
// case.
//
// Known caveats / not-bugs:
//
//   - **TTL / hop-limit unchanged.**  Standard router NAT
//     decrements TTL; we don't, because this is a userspace ferry
//     not a router hop.  Side effect: the original sender's
//     initial-TTL fingerprint leaks to upstream.  Accepted for
//     MVP; revisit if fingerprinting becomes a stated concern.
//   - **Reverse direction is structurally gated.**  `snatReverse`
//     is only called from the joiner→host drain loop, which means
//     the only packets reaching it are those the joiner gvisor
//     stack chose to route out the cascade ferry NIC.  In practice
//     that's upstream-decrypted reply traffic, plus the occasional
//     joiner-generated ICMP error (e.g. Packet Too Big in response
//     to cascade-direction traffic).  A host-stack-sourced packet
//     that happens to address the joiner-own address never enters
//     this path.

package main

import (
	"encoding/binary"
	"net/netip"
	"sync"
)

// NatTable encapsulates the single-peer SNAT state for one cascade
// ferry.  Zero-valued joiner addresses disable NAT for that family.
type NatTable struct {
	mu sync.Mutex

	// joinerOwnV4 / joinerOwnV6 — the joiner's own assigned WG-side
	// address per family.  When the v4 address is the zero-value
	// netip.Addr or not a v4 address, v4 NAT is disabled (and
	// likewise for v6).  Disabling = packets pass through unchanged.
	joinerOwnV4 netip.Addr
	joinerOwnV6 netip.Addr

	// lastSrcV4 / lastSrcV6 — the most-recently-seen original
	// source on the host→joiner direction.  Reverse-direction
	// translation reads these to know who to deliver to.  Single-
	// peer assumption: at most one host-side WG client is sending
	// traffic into the cascade at a time, so the "last seen" is
	// always the right answer.  Multi-peer needs PAT.
	lastSrcV4 netip.Addr
	lastSrcV6 netip.Addr
}

// newNatTable constructs a NAT table.  Either or both joiner
// addresses may be zero — when both are zero the table is a no-op
// passthrough.
func newNatTable(joinerOwnV4, joinerOwnV6 netip.Addr) *NatTable {
	n := &NatTable{}
	n.setJoinerAddrs(joinerOwnV4, joinerOwnV6)
	return n
}

// setJoinerAddrs mutates the configured joiner-own addresses
// in place under lock.  Preserves the `lastSrc*` memory across
// the update.
//
// The preservation matters specifically for the **same-address
// republish** case (the joiner re-runs its configure cycle with
// the same Address), which would otherwise break the reverse
// path of an in-flight flow.  When the joiner's address actually
// CHANGES, the lastSrc* memory becomes effectively unreachable
// — the reverse-path destination check (`origDst != joinerOwn`)
// fires on the new address, so the stale lastSrc* never gets
// applied.  A fresh forward seeds it correctly.
//
// Wrong-family inputs (a v6 address passed as v4 etc.) are
// silently zeroed rather than panic; misconfigured joiner
// shouldn't crash the bridge.
func (n *NatTable) setJoinerAddrs(joinerOwnV4, joinerOwnV6 netip.Addr) {
	if joinerOwnV4.IsValid() && !joinerOwnV4.Is4() {
		joinerOwnV4 = netip.Addr{}
	}
	if joinerOwnV6.IsValid() && !joinerOwnV6.Is6() {
		joinerOwnV6 = netip.Addr{}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.joinerOwnV4 = joinerOwnV4
	n.joinerOwnV6 = joinerOwnV6
	// lastSrcV4 / lastSrcV6 deliberately preserved.
}

// enabledV4 / enabledV6 report whether translation is configured
// for that family.  Exposed for tests.
func (n *NatTable) enabledV4() bool { return n.joinerOwnV4.IsValid() && n.joinerOwnV4.Is4() }
func (n *NatTable) enabledV6() bool { return n.joinerOwnV6.IsValid() && n.joinerOwnV6.Is6() }

// snatForward mutates [raw] (a single IP packet, v4 or v6) so its
// source address becomes the joiner's own address.  Records the
// original source so [snatReverse] can undo the translation on the
// return path.  Returns true if the packet was modified.
//
// Packets where translation isn't configured for the IP family
// pass through unchanged (returns false).  Malformed packets (too
// short, version != 4 || 6) also pass through.
func (n *NatTable) snatForward(raw []byte) bool {
	if len(raw) < 1 {
		return false
	}
	switch raw[0] >> 4 {
	case 4:
		return n.snatV4(raw, true /* forward */)
	case 6:
		return n.snatV6(raw, true /* forward */)
	}
	return false
}

// snatReverse mutates [raw] so its destination address is restored
// to the last-seen original source.  Returns true if the packet was
// modified.  Packets whose destination doesn't match the configured
// joiner-own address pass through unchanged.
func (n *NatTable) snatReverse(raw []byte) bool {
	if len(raw) < 1 {
		return false
	}
	switch raw[0] >> 4 {
	case 4:
		return n.snatV4(raw, false /* reverse */)
	case 6:
		return n.snatV6(raw, false /* reverse */)
	}
	return false
}

// snatV4 handles both directions for an IPv4 packet.
func (n *NatTable) snatV4(raw []byte, forward bool) bool {
	if len(raw) < 20 {
		return false
	}
	ihl := int(raw[0]&0x0f) * 4
	if ihl < 20 || len(raw) < ihl {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.enabledV4() {
		return false
	}
	joinerOwn := n.joinerOwnV4.As4()
	srcOff, dstOff := 12, 16
	origSrc, _ := netip.AddrFromSlice(raw[srcOff : srcOff+4])
	origDst, _ := netip.AddrFromSlice(raw[dstOff : dstOff+4])
	if forward {
		// Forward path: rewrite SRC to joinerOwn.  Remember the
		// original src so reverse-direction can restore it.
		if origSrc == n.joinerOwnV4 {
			// Already in joiner's address space — nothing to do.
			return false
		}
		n.lastSrcV4 = origSrc
		copy(raw[srcOff:srcOff+4], joinerOwn[:])
		fixupV4ChecksumsForSrcChange(raw, ihl, origSrc.As4(), joinerOwn)
		return true
	}
	// Reverse path: only translate when dst matches joinerOwn AND
	// we have a remembered original src.  Otherwise we don't know
	// who this packet is for.
	if origDst != n.joinerOwnV4 || !n.lastSrcV4.IsValid() {
		return false
	}
	remembered := n.lastSrcV4.As4()
	copy(raw[dstOff:dstOff+4], remembered[:])
	fixupV4ChecksumsForDstChange(raw, ihl, joinerOwn, remembered)
	return true
}

// snatV6 handles both directions for an IPv6 packet.  IPv6 has no
// header checksum, but TCP/UDP/ICMPv6 checksums include a pseudo-
// header that covers the IP addresses, so they all need fixup.
func (n *NatTable) snatV6(raw []byte, forward bool) bool {
	if len(raw) < 40 {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.enabledV6() {
		return false
	}
	joinerOwn := n.joinerOwnV6.As16()
	srcOff, dstOff := 8, 24
	var srcBuf, dstBuf [16]byte
	copy(srcBuf[:], raw[srcOff:srcOff+16])
	copy(dstBuf[:], raw[dstOff:dstOff+16])
	origSrc, _ := netip.AddrFromSlice(srcBuf[:])
	origDst, _ := netip.AddrFromSlice(dstBuf[:])
	// NDP (RS/RA/NS/NA — ICMPv6 types 133..137 per RFC 4861)
	// requires the source to be link-local fe80::/10.  Rewriting
	// it to the joiner's global address violates RFC 4861 §3.1
	// AND the receiver's hop-limit-255 check is already
	// untouchable.  Cascade traffic in a WG tunnel shouldn't
	// carry NDP/MLD, but if it does, leave it alone — multicast
	// (ff00::/8) is the other RFC-protected case (MLD reports,
	// ff02::1/2 all-nodes/all-routers).
	if origSrc.IsLinkLocalUnicast() || origDst.IsLinkLocalUnicast() ||
		origSrc.IsMulticast() || origDst.IsMulticast() {
		return false
	}
	if forward {
		if origSrc == n.joinerOwnV6 {
			return false
		}
		// Tentatively apply the SNAT, then refuse and undo if the
		// upper-layer protocol isn't one we can checksum-fix.
		// A SNAT'd-but-checksum-broken packet is worse than a
		// dropped one — receivers silently discard, and we lose
		// the diagnostic that the protocol is unsupported.
		copy(raw[srcOff:srcOff+16], joinerOwn[:])
		if !fixupV6ChecksumsForAddrChange(raw, srcBuf, joinerOwn) {
			copy(raw[srcOff:srcOff+16], srcBuf[:])
			return false
		}
		n.lastSrcV6 = origSrc
		return true
	}
	if origDst != n.joinerOwnV6 || !n.lastSrcV6.IsValid() {
		return false
	}
	remembered := n.lastSrcV6.As16()
	copy(raw[dstOff:dstOff+16], remembered[:])
	if !fixupV6ChecksumsForAddrChange(raw, joinerOwn, remembered) {
		copy(raw[dstOff:dstOff+16], dstBuf[:])
		return false
	}
	return true
}

// fixupV4ChecksumsForSrcChange updates the IP header checksum and
// the TCP/UDP/ICMP checksum (when applicable) after a 4-byte
// source-address change.
func fixupV4ChecksumsForSrcChange(raw []byte, ihl int, oldSrc, newSrc [4]byte) {
	fixupV4HeaderChecksum(raw, oldSrc[:], newSrc[:])
	fixupV4TransportChecksum(raw, ihl, oldSrc[:], newSrc[:])
}

// fixupV4ChecksumsForDstChange updates checksums after a 4-byte
// destination-address change.  TCP/UDP pseudoheaders cover both
// src and dst; ICMP doesn't include addresses in its checksum.
func fixupV4ChecksumsForDstChange(raw []byte, ihl int, oldDst, newDst [4]byte) {
	fixupV4HeaderChecksum(raw, oldDst[:], newDst[:])
	fixupV4TransportChecksum(raw, ihl, oldDst[:], newDst[:])
}

// fixupV4HeaderChecksum applies the incremental-update formula
// (RFC 1624) to the IP header's checksum field after [oldBytes]
// were replaced by [newBytes].
func fixupV4HeaderChecksum(raw []byte, oldBytes, newBytes []byte) {
	const checksumOff = 10
	cs := binary.BigEndian.Uint16(raw[checksumOff : checksumOff+2])
	cs = incrementalChecksumUpdate(cs, oldBytes, newBytes)
	binary.BigEndian.PutUint16(raw[checksumOff:checksumOff+2], cs)
}

// fixupV4TransportChecksum applies the incremental update to the
// TCP/UDP/ICMP-Echo checksum.  TCP/UDP include the IP addresses in
// their pseudo-header so the address change must be reflected.
// ICMP's checksum doesn't include addresses, so we leave it alone
// (the function returns without touching it for that protocol).
//
// Protocol numbers per the IANA registry: 1 = ICMP, 6 = TCP,
// 17 = UDP.
func fixupV4TransportChecksum(raw []byte, ihl int, oldBytes, newBytes []byte) {
	proto := raw[9]
	switch proto {
	case 6: // TCP
		if len(raw) < ihl+18 {
			return
		}
		off := ihl + 16
		cs := binary.BigEndian.Uint16(raw[off : off+2])
		cs = incrementalChecksumUpdate(cs, oldBytes, newBytes)
		binary.BigEndian.PutUint16(raw[off:off+2], cs)
	case 17: // UDP
		if len(raw) < ihl+8 {
			return
		}
		off := ihl + 6
		cs := binary.BigEndian.Uint16(raw[off : off+2])
		// UDP checksum=0 means "not computed" — RFC 768 allows
		// leaving it that way on v4.  Don't activate it.
		if cs == 0 {
			return
		}
		cs = incrementalChecksumUpdate(cs, oldBytes, newBytes)
		// RFC 768: a computed UDP checksum of zero is transmitted
		// as all-ones; preserve that to avoid the "not computed"
		// confusion.
		if cs == 0 {
			cs = 0xffff
		}
		binary.BigEndian.PutUint16(raw[off:off+2], cs)
		// case 1 (ICMP) intentionally not touched — its checksum
		// doesn't cover addresses.
	}
}

// fixupV6ChecksumsForAddrChange updates TCP/UDP/ICMPv6 checksums
// after a 16-byte address change.  IPv6 itself has no header
// checksum.  Returns true if the SNAT was preserved (address
// rewrite stays in place, checksum either updated or correctly
// skipped); false to undo — caller uses the bool to know whether
// the SNAT is safe to inject or whether the receiver will drop
// it for checksum mismatch.
func fixupV6ChecksumsForAddrChange(raw []byte, oldBytes [16]byte, newBytes [16]byte) bool {
	// Walk extension headers to find the upper-layer protocol.
	// For the common case (no extension headers) NextHeader is at
	// offset 6 and the upper layer starts at offset 40.
	proto, off, action := walkV6ExtensionHeaders(raw)
	switch action {
	case v6WalkParseFailure:
		return false
	case v6WalkSkipChecksum:
		// Non-first fragment: bytes at `off` are payload, NOT a
		// transport header.  Rewriting the source address is still
		// correct — the receiver will reassemble all fragments
		// before verifying the upper-layer checksum, and the FIRST
		// fragment (carrying the actual transport header) had its
		// checksum updated normally.  Skipping the fixup here
		// avoids corrupting payload bytes that happen to live at
		// the would-be-checksum offset.
		return true
	}
	switch proto {
	case 6: // TCP
		if len(raw) < off+18 {
			return false
		}
		csOff := off + 16
		cs := binary.BigEndian.Uint16(raw[csOff : csOff+2])
		cs = incrementalChecksumUpdate(cs, oldBytes[:], newBytes[:])
		binary.BigEndian.PutUint16(raw[csOff:csOff+2], cs)
		return true
	case 17: // UDP
		if len(raw) < off+8 {
			return false
		}
		csOff := off + 6
		cs := binary.BigEndian.Uint16(raw[csOff : csOff+2])
		// On IPv6 UDP MUST have a non-zero checksum (RFC 2460).
		// Skip if zero anyway as a defence against malformed input.
		if cs == 0 {
			return false
		}
		cs = incrementalChecksumUpdate(cs, oldBytes[:], newBytes[:])
		if cs == 0 {
			cs = 0xffff
		}
		binary.BigEndian.PutUint16(raw[csOff:csOff+2], cs)
		return true
	case 58: // ICMPv6
		if len(raw) < off+4 {
			return false
		}
		csOff := off + 2
		cs := binary.BigEndian.Uint16(raw[csOff : csOff+2])
		cs = incrementalChecksumUpdate(cs, oldBytes[:], newBytes[:])
		binary.BigEndian.PutUint16(raw[csOff:csOff+2], cs)
		return true
	}
	// Unknown next-header (AH / ESP / Mobility / experimental).
	// We can't compute the checksum offset, so the safe move is
	// to refuse the translation; the caller will drop the packet
	// rather than ship a SNAT'd-but-checksum-broken one.  Cascade
	// traffic in practice is plain TCP/UDP/ICMPv6 inside a WG
	// tunnel, so this branch is the not-supposed-to-happen path.
	return false
}

// v6WalkAction signals what fixupV6ChecksumsForAddrChange should do
// with the (proto, off) returned by walkV6ExtensionHeaders.
type v6WalkAction int

const (
	v6WalkApplyChecksum v6WalkAction = iota // normal: switch on proto
	v6WalkSkipChecksum                      // non-first fragment: rewrite OK, no checksum
	v6WalkParseFailure                      // malformed chain or hop-limit
)

// v6ExtHdrMaxHops bounds the extension-header chain walk to defend
// against malicious or malformed packets whose ext-hdr chain loops
// or grows pathologically long.  RFC 8200 places no upper bound,
// but real cascade traffic carries at most one or two extension
// headers; 8 is generous.
const v6ExtHdrMaxHops = 8

// walkV6ExtensionHeaders follows the IPv6 extension-header chain
// to find the upper-layer protocol.  Returns (protoNumber, offset,
// action) where:
//
//   - action=v6WalkApplyChecksum, proto in {6,17,58}: caller
//     applies the matching checksum fixup at [off].
//   - action=v6WalkSkipChecksum: this packet is a non-first fragment;
//     [off] points at payload bytes (not a transport header), so
//     the caller MUST NOT touch the checksum.  The address-only
//     rewrite is still correct because reassembled-datagram-level
//     checksum verification happens after reassembly.
//   - action=v6WalkParseFailure: malformed chain or exceeds the
//     v6ExtHdrMaxHops cap; caller undoes the SNAT.
//
// Handles the common extension header types: Hop-by-Hop (0),
// Routing (43), Fragment (44), Destination Options (60).  Doesn't
// follow AH / ESP — they trigger unknown-next-header in the caller,
// which undoes the SNAT.
func walkV6ExtensionHeaders(raw []byte) (proto byte, off int, action v6WalkAction) {
	if len(raw) < 40 {
		return 0, 0, v6WalkParseFailure
	}
	cur := raw[6]
	off = 40
	for hops := 0; hops < v6ExtHdrMaxHops; hops++ {
		switch cur {
		case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options
			if off+2 > len(raw) {
				return 0, 0, v6WalkParseFailure
			}
			cur = raw[off]
			// RFC 8200 §4: "Length of the … header in 8-octet
			// units, not including the first 8 octets", so the
			// in-bytes length is (HdrExtLen + 1) * 8.
			extLen := (int(raw[off+1]) + 1) * 8
			off += extLen
			if off > len(raw) {
				return 0, 0, v6WalkParseFailure
			}
		case 44: // Fragment header is fixed 8 bytes
			if off+8 > len(raw) {
				return 0, 0, v6WalkParseFailure
			}
			// Fragment offset is bits 0..12 of the 16-bit field
			// at off+2..off+3 (8-byte units; bottom 3 bits are
			// Res+M flag).
			fragWord := binary.BigEndian.Uint16(raw[off+2 : off+4])
			fragOffset := fragWord >> 3
			cur = raw[off]
			off += 8
			if fragOffset != 0 {
				// Non-first fragment: the bytes at `off` are
				// payload data — the transport header (and its
				// checksum field) live in the FIRST fragment.
				// Tell the caller to keep the address rewrite
				// but skip the checksum fixup.
				return cur, off, v6WalkSkipChecksum
			}
		default:
			return cur, off, v6WalkApplyChecksum
		}
	}
	// Hop cap reached — refuse the packet rather than risk an
	// unbounded loop or wedged drain goroutine.
	return 0, 0, v6WalkParseFailure
}

// incrementalChecksumUpdate applies RFC 1624 / Eqn 4 to update an
// internet checksum after a region of the covered data has changed.
//
// The formula in one's-complement arithmetic:
//
//   HC' = ~( ~HC + ~old + new )
//
// where HC is the existing checksum, old is the original 16-bit
// word, new is the replacement, and ~ is bitwise NOT.  We operate
// over an arbitrary-length byte buffer by treating it as a sequence
// of 16-bit words (with an odd trailing byte zero-padded).
func incrementalChecksumUpdate(cs uint16, oldBytes, newBytes []byte) uint16 {
	// Carry-accumulator (~32 bit) of [~cs + sum(~old) + sum(new)].
	acc := uint32(^cs)
	acc += sumOnesComplement(oldBytes, true /* invert */)
	acc += sumOnesComplement(newBytes, false /* don't invert */)
	// Fold carries.
	for acc>>16 != 0 {
		acc = (acc & 0xffff) + (acc >> 16)
	}
	return ^uint16(acc)
}

// sumOnesComplement sums a byte slice as a sequence of 16-bit
// big-endian words.  If [invert] is true, the words are inverted
// before summing (i.e., sum of ~old in the RFC 1624 formula).
//
// Callers must pass even-length slices.  The NAT use case is
// IP-address rewrites (4 or 16 bytes), which are always even —
// supporting odd-length input would require a from-scratch
// recompute on the full buffer to know the parity of the
// preceding bytes, which defeats the point of an incremental
// update.  Panics on odd input to fail loudly if a future
// caller violates the contract.
func sumOnesComplement(b []byte, invert bool) uint32 {
	if len(b)&1 != 0 {
		panic("sumOnesComplement: caller passed odd-length slice; incremental " +
			"update only supports word-aligned regions")
	}
	var acc uint32
	for i := 0; i < len(b); i += 2 {
		w := uint32(b[i])<<8 | uint32(b[i+1])
		if invert {
			w = ^w & 0xffff
		}
		acc += w
	}
	return acc
}
