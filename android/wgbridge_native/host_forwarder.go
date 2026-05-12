// Through-host packet forwarder ("Option B").
//
// gvisor's TCP/UDP forwarders only fire for locally-assigned dsts.
// A full-tunnel joiner's traffic to 1.1.1.1 etc. would otherwise
// be dropped at the IP layer. We add a second virtual NIC, route
// non-WG-subnet traffic there, drain it in a goroutine, and:
// - ICMP echo: do a real outbound ping via SOCK_DGRAM and inject
// the synthesised reply back through NIC1 (WritePackets, which
// bypasses netstack routing so the same-NIC anti-loop check
// doesn't drop us). Preserve the joiner's original ident.
// - TCP / UDP: register dst as a *temporary local address* on
// NIC1 (gvstack.AddressProperties{Temporary: true}) then
// InjectInbound — gvisor's catchall transport handlers fire on
// the next round + NAT through real OS sockets.
//
// Temp addresses accumulate over the bridge's lifetime (bounded in
// practice by the joiner's browsing pattern; cleared on bridge
// restart). See memory project_gvisor_through_host_forwarding.md
// for the full design + validation history.

package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	icmpx "golang.org/x/net/icmp"
	netipv4 "golang.org/x/net/ipv4"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gvchannel "gvisor.dev/gvisor/pkg/tcpip/link/channel"
	gvipv4 "gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	gvstack "gvisor.dev/gvisor/pkg/tcpip/stack"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	// NIC2 channel-endpoint capacity (packets buffered). Sized
	// generously — gvisor's forwarding goroutine drains in tight
	// loop, but a burst of fan-out can still queue briefly.
	nic2QueueDepth = 2048

	// MTU fallback when wireguard-go's TUN doesn't report one.
	defaultIPv4MTU = 1500

	// Cadence + idle-poll for the forwarder loop.
	heartbeatInterval = 10 * time.Second
	emptyQueuePoll = 10 * time.Millisecond

	// Linux IANA protocol number for ICMPv4 (icmp.ParseMessage
	// takes IANA, NOT gvisor's NetworkProtocolNumber).
	protoICMPv4 = 1
)

type hostForwarderState struct {
	closed atomic.Bool
	stk *gvstack.Stack
	origNICID tcpip.NICID // NIC1 — wireguard-go's TUN
	outNICID tcpip.NICID // NIC2 — virtual outbound NIC
	outEp *gvchannel.Endpoint
	inEp *gvchannel.Endpoint
	origRoutes []tcpip.Route
	stop context.CancelFunc
	pingWg sync.WaitGroup
	ctx context.Context
	pingTimeout time.Duration
	// Destination IPs we've registered as temporary local
	// addresses on NIC1. Mutex covers both the map and the
	// AddProtocolAddress call.
	tempAddrMu sync.Mutex
	tempAddrs map[tcpip.Address]bool
	// Counters (internal — useful for diagnostics + future
	// rate-limit gauges; not exported via JNI).
	pktsSeen atomic.Int64
	pingsSent atomic.Int64
	pingsRpld atomic.Int64
	injectsOK atomic.Int64
	tcpRedirs atomic.Int64
	udpRedirs atomic.Int64
	tempAddrN atomic.Int64
}

func extractChannelEndpoint(n *netstack.Net) *gvchannel.Endpoint {
	v := reflect.ValueOf(n).Elem()
	f := v.FieldByName("ep")
	if !f.IsValid() || f.Kind() != reflect.Ptr {
		return nil
	}
	ptr := unsafe.Pointer(f.UnsafeAddr())
	return *(**gvchannel.Endpoint)(ptr)
}

// wgbridgeInstallHostForwarder installs the Option B host
// forwarder on the bridge identified by [handle]. [peerSubnet]
// (CIDR, e.g. "10.99.0.0/24") is the WG-side subnet kept on NIC1;
// everything else gets routed via NIC2 + the forwarder goroutine.
//
// Returns:
//
//	> 0 : forwarder handle (close via wgbridgeCloseListener)
//	 -1 : invalid bridge handle
//	 -2 : bridge is not host-mode (no netstack)
//	 -3 : netstack internal layout unexpected
//	 -4 : peerSubnet parse failed
//	 -5 : CreateNIC failed (port collision / OOM)
//
//export wgbridgeInstallHostForwarder
func wgbridgeInstallHostForwarder(handle C.int,
	peerSubnetStr *C.char, peerSubnetLen C.int) C.int {
	bs := lookupHandle(int32(handle))
	if bs == nil {
		return -1
	}
	if bs.tnet == nil {
		return -2
	}
	stk := extractStack(bs.tnet)
	if stk == nil {
		return -3
	}
	inEp := extractChannelEndpoint(bs.tnet)
	if inEp == nil {
		return -3
	}
	peerSubnetGo := C.GoStringN(peerSubnetStr, C.int(peerSubnetLen))
	_, ipnet, err := net.ParseCIDR(peerSubnetGo)
	if err != nil {
		return -4
	}
	ipv4Net := ipnet.IP.To4()
	if ipv4Net == nil {
		return -4
	}

	// New NIC ID, one higher than any existing.
	nicInfos := stk.NICInfo()
	var maxID, origID tcpip.NICID
	for id := range nicInfos {
		if id > maxID {
			maxID = id
		}
		if origID == 0 {
			origID = id
		}
	}
	newNICID := maxID + 1

	mtu, mtuErr := bs.tunDev.MTU()
	if mtuErr != nil || mtu <= 0 {
		mtu = defaultIPv4MTU
	}
	outEp := gvchannel.New(nic2QueueDepth, uint32(mtu), "")
	if tcpErr := stk.CreateNIC(newNICID, outEp); tcpErr != nil {
		return -5
	}

	peerAddr := tcpip.AddrFromSlice(ipv4Net)
	maskBits, _ := ipnet.Mask.Size()
	peerMask := tcpip.MaskFromBytes(net.CIDRMask(maskBits, 32))
	peerSubnet, snErr := tcpip.NewSubnet(peerAddr, peerMask)
	if snErr != nil {
		stk.RemoveNIC(newNICID)
		return -4
	}
	origRoutes := append([]tcpip.Route(nil), stk.GetRouteTable()...)
	stk.SetRouteTable([]tcpip.Route{
		{Destination: peerSubnet, NIC: origID},
		{Destination: header.IPv4EmptySubnet, NIC: newNICID},
	})
	stk.SetForwardingDefaultAndAllNICs(gvipv4.ProtocolNumber, true)

	ctx, cancel := context.WithCancel(context.Background())
	state := &hostForwarderState{
		stk: stk, origNICID: origID, outNICID: newNICID,
		outEp: outEp, inEp: inEp,
		origRoutes: origRoutes, stop: cancel, ctx: ctx,
		pingTimeout: 2 * time.Second,
		tempAddrs: make(map[tcpip.Address]bool),
	}
	ls := &listenerState{
		kind: listenerKindHostForwarder,
		bridgeID: int32(handle),
	}
	ls.hostFwd = state
	id := allocateListenerHandle(ls)
	// gvisor's IP-layer ICMP auto-reply skips temp-local addrs —
	// our handler covers that gap (see handleLocalICMP).
	stk.SetTransportProtocolHandler(header.ICMPv4ProtocolNumber,
		state.handleLocalICMP)
	go state.run(ls)
	hostFwdLog("host forwarder installed (NIC=%d, peerSubnet=%s)",
		newNICID, peerSubnetGo)
	return C.int(id)
}

func (s *hostForwarderState) run(ls *listenerState) {
	hostFwdLog("forwarder loop starting on NIC %d", s.outNICID)
	// Heartbeat — exposes the forwarder's pulse to logcat so a
	// real-device hang is distinguishable from "no traffic".
	go func() {
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				if s.closed.Load() {
					return
				}
				hostFwdLog("heartbeat: pktsSeen=%d ping(sent=%d rpld=%d inj=%d) tcpRedir=%d udpRedir=%d tempAddrs=%d",
					s.pktsSeen.Load(),
					s.pingsSent.Load(),
					s.pingsRpld.Load(),
					s.injectsOK.Load(),
					s.tcpRedirs.Load(),
					s.udpRedirs.Load(),
					s.tempAddrN.Load())
			}
		}
	}()
	for {
		if s.closed.Load() || ls.closed.Load() {
			hostFwdLog("forwarder loop exiting (closed)")
			return
		}
		pkt := s.outEp.Read()
		if pkt == nil {
			select {
			case <-s.ctx.Done():
				return
			case <-time.After(emptyQueuePoll):
			}
			continue
		}
		s.pktsSeen.Add(1)
		s.handleOutbound(pkt)
		pkt.DecRef()
	}
}

func (s *hostForwarderState) handleOutbound(pkt *gvstack.PacketBuffer) {
	bufV := pkt.ToView()
	if bufV == nil {
		return
	}
	defer bufV.Release()
	raw := bufV.AsSlice()
	if len(raw) < header.IPv4MinimumSize {
		return
	}
	ip := header.IPv4(raw)
	if !ip.IsValid(len(raw)) {
		return
	}
	srcAddr := ip.SourceAddress()
	dstAddr := ip.DestinationAddress()
	srcSlice := srcAddr.AsSlice()
	dstSlice := dstAddr.AsSlice()
	proto := ip.Protocol()
	switch proto {
	case uint8(header.ICMPv4ProtocolNumber):
		s.handleOutboundICMP(ip, raw)
	case uint8(header.TCPProtocolNumber):
		hostFwdLog("NIC2 TCP %v -> %v (len=%d) — redirecting",
			net.IP(srcSlice), net.IP(dstSlice), len(raw))
		s.redirectViaTempAddress(dstAddr, raw)
		s.tcpRedirs.Add(1)
	case uint8(header.UDPProtocolNumber):
		hostFwdLog("NIC2 UDP %v -> %v (len=%d) — redirecting",
			net.IP(srcSlice), net.IP(dstSlice), len(raw))
		s.redirectViaTempAddress(dstAddr, raw)
		s.udpRedirs.Add(1)
	default:
		hostFwdLog("NIC2 proto=%d %v -> %v (len=%d) — DROPPED (unsupported)",
			proto, net.IP(srcSlice), net.IP(dstSlice), len(raw))
	}
}

// handleOutboundICMP synthesises an echo-reply for outbound ICMP
// echo requests. Real ICMP via `SOCK_DGRAM/IPPROTO_ICMP`; the
// reply goes back via `WritePackets` (not InjectInbound — that
// triggers same-NIC anti-loop drops).
func (s *hostForwarderState) handleOutboundICMP(ip header.IPv4, raw []byte) {
	ihl := int(ip.HeaderLength())
	if ihl < header.IPv4MinimumSize || ihl > len(raw) {
		return
	}
	icmpBytes := raw[ihl:]
	if len(icmpBytes) < header.ICMPv4MinimumSize {
		return
	}
	icmpHdr := header.ICMPv4(icmpBytes)
	if icmpHdr.Type() != header.ICMPv4Echo || icmpHdr.Code() != 0 {
		return
	}
	srcAddr := ip.SourceAddress()
	dstAddr := ip.DestinationAddress()
	srcIP := net.IP(srcAddr.AsSlice()).To4()
	dstIP := net.IP(dstAddr.AsSlice()).To4()
	if srcIP == nil || dstIP == nil {
		return
	}
	ident := icmpHdr.Ident()
	seq := icmpHdr.Sequence()
	payload := append([]byte(nil), icmpHdr.Payload()...)
	hostFwdLog("outbound ICMP echo %v -> %v ident=%d seq=%d",
		srcIP, dstIP, ident, seq)
	s.pingWg.Add(1)
	go func() {
		defer s.pingWg.Done()
		s.dispatchPing(srcIP, dstIP, ident, seq, payload)
	}()
}

// redirectViaTempAddress is the TCP/UDP path. Registers dst as
// a temp local address on NIC1, then re-injects the bytes via
// NIC1's channel endpoint. gvisor's existing TCP/UDP catchall
// handlers fire on the next round; the Kotlin-side handlers do
// real OS-socket NAT.
func (s *hostForwarderState) redirectViaTempAddress(dst tcpip.Address, raw []byte) {
	s.ensureTempLocalAddress(dst)
	// Clone — the netstack consumes/decref's the PacketBuffer
	// we hand to InjectInbound.
	bytesCopy := make([]byte, len(raw))
	copy(bytesCopy, raw)
	buf := buffer.MakeWithData(bytesCopy)
	injectPkt := gvstack.NewPacketBuffer(gvstack.PacketBufferOptions{
		Payload: buf,
	})
	dstSlice := dst.AsSlice()
	hostFwdLog("re-injecting %dB on NIC1 (dst=%v, proto=%d)",
		len(raw), net.IP(dstSlice), raw[9])
	s.inEp.InjectInbound(gvipv4.ProtocolNumber, injectPkt)
	injectPkt.DecRef()
}

func (s *hostForwarderState) ensureTempLocalAddress(addr tcpip.Address) {
	s.tempAddrMu.Lock()
	defer s.tempAddrMu.Unlock()
	if s.tempAddrs[addr] {
		return
	}
	s.tempAddrs[addr] = true
	protoAddr := tcpip.ProtocolAddress{
		Protocol: gvipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address: addr,
			PrefixLen: 32,
		},
	}
	if err := s.stk.AddProtocolAddress(s.origNICID, protoAddr,
		gvstack.AddressProperties{Temporary: true}); err != nil {
		hostFwdLog("AddProtocolAddress(%v) failed: %v", addr, err)
		return
	}
	s.tempAddrN.Add(1)
	hostFwdLog("registered temp local addr %v", addr)
}

func (s *hostForwarderState) dispatchPing(
	srcIP, dstIP net.IP, ident, seq uint16, payload []byte,
) {
	s.pingsSent.Add(1)
	conn, err := icmpx.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		hostFwdLog("ListenPacket failed: %v", err)
		return
	}
	defer conn.Close()
	out := &icmpx.Message{
		Type: netipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmpx.Echo{ID: int(ident), Seq: int(seq), Data: payload},
	}
	outBytes, err := out.Marshal(nil)
	if err != nil {
		return
	}
	if _, err := conn.WriteTo(outBytes, &net.UDPAddr{IP: dstIP}); err != nil {
		hostFwdLog("WriteTo %v failed: %v", dstIP, err)
		return
	}
	if err := conn.SetReadDeadline(time.Now().Add(s.pingTimeout)); err != nil {
		return
	}
	rb := make([]byte, 1500)
	n, _, err := conn.ReadFrom(rb)
	if err != nil || n <= 0 {
		hostFwdLog("ReadFrom %v failed: err=%v n=%d (no upstream reply within %v)",
			dstIP, err, n, s.pingTimeout)
		return
	}
	s.pingsRpld.Add(1)
	msg, err := icmpx.ParseMessage(protoICMPv4, rb[:n])
	if err != nil {
		hostFwdLog("ParseMessage failed: %v", err)
		return
	}
	if msg.Type != netipv4.ICMPTypeEchoReply {
		return
	}
	echo, ok := msg.Body.(*icmpx.Echo)
	if !ok {
		return
	}
	// IMPORTANT: pass the joiner's original `ident`, not
	// `echo.ID` — the kernel rewrites the ident on the
	// unprivileged ICMP socket, so the value we just received
	// is the kernel-NAT'd one rather than what the joiner expects.
	s.injectEchoReply(dstIP, srcIP, ident, uint16(echo.Seq), echo.Data)
}

func (s *hostForwarderState) injectEchoReply(
	src, dst net.IP, ident, seq uint16, payload []byte,
) {
	if s.closed.Load() {
		return
	}
	pktBytes := buildIPv4ICMPEchoReply(src, dst, ident, seq, payload)
	buf := buffer.MakeWithData(pktBytes)
	pkt := gvstack.NewPacketBuffer(gvstack.PacketBufferOptions{Payload: buf})
	var pkts gvstack.PacketBufferList
	pkts.PushBack(pkt)
	s.inEp.WritePackets(pkts)
	pkt.DecRef()
	s.injectsOK.Add(1)
	hostFwdLog("injected echo-reply %v -> %v ident=%d seq=%d (payload=%dB)",
		src, dst, ident, seq, len(payload))
}

// buildIPv4ICMPEchoReply constructs a complete IPv4+ICMP echo
// reply. The ICMP checksum covers the full segment (header +
// payload); see TestBuildIPv4ICMPEchoReplyChecksum.
func buildIPv4ICMPEchoReply(
	src, dst net.IP, ident, seq uint16, payload []byte,
) []byte {
	totalLen := header.IPv4MinimumSize + header.ICMPv4MinimumSize + len(payload)
	pktBytes := make([]byte, totalLen)
	ip := header.IPv4(pktBytes[:header.IPv4MinimumSize])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL: 64,
		Protocol: uint8(header.ICMPv4ProtocolNumber),
		SrcAddr: tcpip.AddrFromSlice(src.To4()),
		DstAddr: tcpip.AddrFromSlice(dst.To4()),
	})
	ip.SetChecksum(0)
	ip.SetChecksum(^ip.CalculateChecksum())
	icmpStart := header.IPv4MinimumSize
	fullIcmp := header.ICMPv4(pktBytes[icmpStart:])
	fullIcmp.SetType(header.ICMPv4EchoReply)
	fullIcmp.SetCode(0)
	fullIcmp.SetIdent(ident)
	fullIcmp.SetSequence(seq)
	copy(pktBytes[icmpStart+header.ICMPv4MinimumSize:], payload)
	fullIcmp.SetChecksum(0)
	fullIcmp.SetChecksum(header.ICMPv4Checksum(fullIcmp, 0))
	return pktBytes
}

// handleLocalICMP fires for ICMPv4 packets whose dst is locally
// assigned on NIC1. Two cases:
// - Real-local dst (e.g. 10.99.0.1) → no-op; gvisor auto-replies.
// - Temp-local dst (registered by redirectViaTempAddress) →
// gvisor's IP-layer skips auto-reply for these, so we forward
// to the real internet and synthesise the reply ourselves.
//
// Stays registered for the bridge's lifetime — gvisor has no
// unregister API — so closed.Load() must short-circuit cleanly.
// pkt.Data() uses ToSlice (ToView returns nil for empty payloads,
// which then panics on Release). Return value is unused by gvisor
// for this code path; always false.
func (s *hostForwarderState) handleLocalICMP(
	id gvstack.TransportEndpointID, pkt *gvstack.PacketBuffer,
) bool {
	if s.closed.Load() {
		return false
	}
	if !pkt.NetworkPacketInfo.LocalAddressTemporary {
		// Real-local — leave it for gvisor's auto-reply.
		return false
	}
	icmpBytes := pkt.TransportHeader().Slice()
	if len(icmpBytes) < header.ICMPv4MinimumSize {
		return false
	}
	icmpHdr := header.ICMPv4(icmpBytes)
	if icmpHdr.Type() != header.ICMPv4Echo || icmpHdr.Code() != 0 {
		return false
	}
	ipBytes := pkt.NetworkHeader().Slice()
	if len(ipBytes) < header.IPv4MinimumSize {
		return false
	}
	ipHdr := header.IPv4(ipBytes)
	srcAddr := ipHdr.SourceAddress()
	dstAddr := ipHdr.DestinationAddress()
	srcIP := net.IP(srcAddr.AsSlice()).To4()
	dstIP := net.IP(dstAddr.AsSlice()).To4()
	if srcIP == nil || dstIP == nil {
		return false
	}
	ident := icmpHdr.Ident()
	seq := icmpHdr.Sequence()
	// ToSlice, not ToView: ToView returns nil on empty payloads
	// and Release panics on nil. See TestEmptyPayloadToSliceVsToView.
	payload := pkt.Data().AsRange().ToSlice()
	hostFwdLog("ICMP echo (temp-local) %v -> %v ident=%d seq=%d payload=%dB",
		srcIP, dstIP, ident, seq, len(payload))
	s.pingWg.Add(1)
	go func() {
		defer s.pingWg.Done()
		s.dispatchPing(srcIP, dstIP, ident, seq, payload)
	}()
	return false
}

func (s *hostForwarderState) closeForwarder() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	s.stop()
	s.pingWg.Wait()
	s.stk.SetRouteTable(s.origRoutes)
	s.stk.RemoveNIC(s.outNICID)
}
