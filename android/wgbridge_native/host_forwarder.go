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
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	icmpx "golang.org/x/net/icmp"
	netipv4 "golang.org/x/net/ipv4"
	netipv6 "golang.org/x/net/ipv6"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gvchannel "gvisor.dev/gvisor/pkg/tcpip/link/channel"
	gvipv4 "gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	gvipv6 "gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
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
	// Linux IANA protocol number for ICMPv6 / IPv6-ICMP. Same
	// distinction: icmp.ParseMessage takes IANA values.
	protoICMPv6 = 58
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
	// V6.H2b — counts packets dropped because the IP version or
	// next-header isn't one we handle (e.g. IPv6 Fragment).
	// Exposed for diagnostic tests (`TestHandleOutboundDispatches…`)
	// to actively assert the DROP branch fired rather than
	// inferring it from the absence of other counter changes.
	unsupportedDrops atomic.Int64
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
// forwarder on the bridge identified by [handle].  `peerSubnet`
// is the WG-side subnet(s) kept on NIC1; everything else gets
// routed via NIC2 + the forwarder goroutine.
//
// V6.H2b: `peerSubnet` is now a comma-separated CIDR list
// (e.g. `"10.99.0.0/24,fd00:dead:beef::/64"`) — same wire format
// as `wgbridgeNew` (V6.H1).  Whitespace tolerated on input.  When
// a v6 entry is present, the forwarder also installs a v6 route +
// enables ipv6 forwarding + registers the ICMPv6 transport handler
// so non-local v6 destinations route through the same forwarder
// goroutine as v4.
//
// Returns:
//
//	> 0 : forwarder handle (close via wgbridgeCloseListener)
//	 -1 : invalid bridge handle
//	 -2 : bridge is not host-mode (no netstack)
//	 -3 : netstack internal layout unexpected
//	 -4 : peerSubnet parse failed (or none of the comma entries
//	      parsed; at least one v4 OR v6 CIDR is required)
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
	peerSubnetsGo := C.GoStringN(peerSubnetStr, C.int(peerSubnetLen))
	// V6.H2b — split on comma + trim each entry (whitespace
	// tolerated on input but never emitted on output).  Sort
	// entries by family so we have at most one v4 + at most one
	// v6.  Extra entries of the same family are silently ignored;
	// in practice the caller produces exactly one of each.
	var v4Net, v6Net *net.IPNet
	for _, part := range strings.Split(peerSubnetsGo, ",") {
		s := strings.TrimSpace(part)
		if s == "" {
			continue
		}
		_, ipn, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		if ipn.IP.To4() != nil {
			if v4Net == nil {
				v4Net = ipn
			}
		} else if len(ipn.IP) == 16 {
			if v6Net == nil {
				v6Net = ipn
			}
		}
	}
	if v4Net == nil && v6Net == nil {
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

	// Build the route table.  V4 always covers the host's WG
	// subnet → NIC1 + a default → NIC2.  V6 (when present) adds
	// the v6 prefix → NIC1 + a v6 default → NIC2.  The two
	// defaults coexist: gvisor's per-family route matching picks
	// the right one based on the packet's network protocol.
	routes := []tcpip.Route{}
	if v4Net != nil {
		ipv4Bytes := v4Net.IP.To4()
		peerAddr := tcpip.AddrFromSlice(ipv4Bytes)
		maskBits, _ := v4Net.Mask.Size()
		peerMask := tcpip.MaskFromBytes(net.CIDRMask(maskBits, 32))
		peerSubnet, snErr := tcpip.NewSubnet(peerAddr, peerMask)
		if snErr != nil {
			stk.RemoveNIC(newNICID)
			return -4
		}
		routes = append(routes,
			tcpip.Route{Destination: peerSubnet, NIC: origID},
			tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: newNICID},
		)
	}
	if v6Net != nil {
		// IP slice is already 16 bytes for v6.
		peerAddr := tcpip.AddrFromSlice(v6Net.IP)
		maskBits, _ := v6Net.Mask.Size()
		peerMask := tcpip.MaskFromBytes(net.CIDRMask(maskBits, 128))
		peerSubnet, snErr := tcpip.NewSubnet(peerAddr, peerMask)
		if snErr != nil {
			stk.RemoveNIC(newNICID)
			return -4
		}
		routes = append(routes,
			tcpip.Route{Destination: peerSubnet, NIC: origID},
			tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: newNICID},
		)
	}
	origRoutes := append([]tcpip.Route(nil), stk.GetRouteTable()...)
	stk.SetRouteTable(routes)
	stk.SetForwardingDefaultAndAllNICs(gvipv4.ProtocolNumber, true)
	if v6Net != nil {
		stk.SetForwardingDefaultAndAllNICs(gvipv6.ProtocolNumber, true)
	}

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
	if v6Net != nil {
		// V6.H2b — same temp-local-addr ICMP gap exists for v6;
		// install the sibling handler.
		stk.SetTransportProtocolHandler(header.ICMPv6ProtocolNumber,
			state.handleLocalICMPv6)
	}
	go state.run(ls)
	hostFwdLog("host forwarder installed (NIC=%d, peerSubnets=%q v6=%v)",
		newNICID, peerSubnetsGo, v6Net != nil)
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
				hostFwdLog("heartbeat: pktsSeen=%d ping(sent=%d rpld=%d inj=%d) tcpRedir=%d udpRedir=%d tempAddrs=%d unsupportedDrops=%d",
					s.pktsSeen.Load(),
					s.pingsSent.Load(),
					s.pingsRpld.Load(),
					s.injectsOK.Load(),
					s.tcpRedirs.Load(),
					s.udpRedirs.Load(),
					s.tempAddrN.Load(),
					s.unsupportedDrops.Load())
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
	if len(raw) < 1 {
		return
	}
	// IP version sits in the top nibble of byte 0 (RFC 791 §3.1 /
	// RFC 8200 §3).  V6.H2b — dispatch v6 to the v6 handler path
	// rather than dropping with "unsupported" the way pre-V6 code
	// did when wireguard-go's TUN started carrying mixed-family
	// inner traffic.
	switch raw[0] >> 4 {
	case 4:
		s.handleOutboundV4(raw)
	case 6:
		s.handleOutboundV6(raw)
	default:
		hostFwdLog("NIC2 unknown IP version %d (len=%d) — DROPPED",
			raw[0]>>4, len(raw))
		s.unsupportedDrops.Add(1)
	}
}

func (s *hostForwarderState) handleOutboundV4(raw []byte) {
	if len(raw) < header.IPv4MinimumSize {
		return
	}
	ip := header.IPv4(raw)
	if !ip.IsValid(len(raw)) {
		return
	}
	srcAddr := ip.SourceAddress()
	dstAddr := ip.DestinationAddress()
	srcSlice := addrSliceLocal(srcAddr)
	dstSlice := addrSliceLocal(dstAddr)
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
		s.unsupportedDrops.Add(1)
	}
}

// handleOutboundV6 mirrors [handleOutboundV4] for IPv6.  Parses
// the IPv6 fixed header, dispatches ICMPv6 echo via the v6 ping
// helper, redirects TCP/UDP via temp-local v6 addresses on NIC1.
//
// V6.H2b: this is the entry point for through-host v6 forwarding.
// Non-local v6 dsts (anything outside the host's `subnetV6`) reach
// NIC2 via the route table installed by `wgbridgeInstallHostForwarder`;
// without this handler they'd be silently dropped by gvisor's IPv6
// forwarder.
func (s *hostForwarderState) handleOutboundV6(raw []byte) {
	if len(raw) < header.IPv6MinimumSize {
		return
	}
	ip := header.IPv6(raw)
	if !ip.IsValid(len(raw)) {
		return
	}
	srcAddr := ip.SourceAddress()
	dstAddr := ip.DestinationAddress()
	srcSlice := addrSliceLocal(srcAddr)
	dstSlice := addrSliceLocal(dstAddr)
	// IPv6 may carry extension headers between the fixed header
	// and the transport segment.  We only handle the "no extension
	// headers" case here — ICMPv6 echo from a stock Linux/Android
	// joiner doesn't include any.  If a future joiner needs HBH /
	// Routing / Fragment headers, this branch would need a full
	// extension-header walk (RFC 8200 §4).
	nextHdr := ip.NextHeader()
	switch nextHdr {
	case uint8(header.ICMPv6ProtocolNumber):
		s.handleOutboundICMPv6(ip, raw)
	case uint8(header.TCPProtocolNumber):
		hostFwdLog("NIC2 v6 TCP %v -> %v (len=%d) — redirecting",
			net.IP(srcSlice), net.IP(dstSlice), len(raw))
		s.redirectViaTempAddressV6(dstAddr, raw)
		s.tcpRedirs.Add(1)
	case uint8(header.UDPProtocolNumber):
		hostFwdLog("NIC2 v6 UDP %v -> %v (len=%d) — redirecting",
			net.IP(srcSlice), net.IP(dstSlice), len(raw))
		s.redirectViaTempAddressV6(dstAddr, raw)
		s.udpRedirs.Add(1)
	default:
		// TODO V6.H2c: extension header walk (RFC 8200 §4).
		// Fragment (44) is the most common one we'd see from a
		// joiner that fragments a >MTU outbound datagram.  Today
		// we drop it — the joiner sees half the response missing
		// and times out at the application layer.  Not a v0.2.x
		// blocker because stock Linux/Android `ping6` doesn't
		// fragment, but worth fixing before bulk-UDP workloads.
		hostFwdLog("NIC2 v6 next-hdr=%d %v -> %v (len=%d) — DROPPED (unsupported)",
			nextHdr, net.IP(srcSlice), net.IP(dstSlice), len(raw))
		s.unsupportedDrops.Add(1)
	}
}

// addrSliceLocal is the production sibling of the test helper.
// gvisor's `tcpip.Address.AsSlice` is a pointer method since
// 2025-05; calling it on a temporary (`ip.SourceAddress().AsSlice()`)
// fails to compile.  Storing the address in a parameter makes it
// addressable.
func addrSliceLocal(a tcpip.Address) []byte { return a.AsSlice() }

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

// handleOutboundICMPv6 — v6 sibling of [handleOutboundICMP].
// Synthesises an echo-reply for outbound ICMPv6 echo requests by
// doing a real outbound ping (SOCK_DGRAM/IPPROTO_ICMPV6 via
// `icmpx.ListenPacket("udp6", "::")`) and injecting the reply
// back through NIC1's channel endpoint with `WritePackets`.
//
// V6.H2b: mirrors the v4 path's ident-preservation trick — the
// kernel rewrites the ident on outbound ICMPv6, so we cache the
// joiner's original ident and re-stamp it on the synthesised
// reply.
func (s *hostForwarderState) handleOutboundICMPv6(ip header.IPv6, raw []byte) {
	icmpStart := header.IPv6MinimumSize
	if len(raw) < icmpStart+header.ICMPv6MinimumSize {
		return
	}
	icmpBytes := raw[icmpStart:]
	icmpHdr := header.ICMPv6(icmpBytes)
	if icmpHdr.Type() != header.ICMPv6EchoRequest || icmpHdr.Code() != 0 {
		return
	}
	srcAddr := ip.SourceAddress()
	dstAddr := ip.DestinationAddress()
	srcIP := net.IP(addrSliceLocal(srcAddr))
	dstIP := net.IP(addrSliceLocal(dstAddr))
	if len(srcIP) != 16 || len(dstIP) != 16 {
		return
	}
	ident := icmpHdr.Ident()
	seq := icmpHdr.Sequence()
	// Slice the payload past the 8-byte ICMPv6 header.  Defensive
	// copy: the underlying packet buffer is consumed before the
	// goroutine runs.
	payload := append([]byte(nil), icmpHdr.Payload()...)
	hostFwdLog("outbound ICMPv6 echo %v -> %v ident=%d seq=%d",
		srcIP, dstIP, ident, seq)
	s.pingWg.Add(1)
	go func() {
		defer s.pingWg.Done()
		s.dispatchPingV6(srcIP, dstIP, ident, seq, payload)
	}()
}

// dispatchPingV6 — v6 sibling of [dispatchPing].  Opens an
// unprivileged ICMPv6 socket, sends the echo request to [dstIP],
// and waits up to `s.pingTimeout` for the reply.  On success,
// injects a synthesised echo-reply back to the joiner.
//
// The `udp6` network spec is misleading: under the hood this opens
// a `SOCK_DGRAM/IPPROTO_ICMPV6` socket (Linux's unprivileged ICMP
// path, RFC 6334 / kernel commit c319b4d76b9e), NOT a UDP socket.
// `icmpx.ListenPacket` paper-tigers the choice of dgram vs raw
// per protocol.
func (s *hostForwarderState) dispatchPingV6(
	srcIP, dstIP net.IP, ident, seq uint16, payload []byte,
) {
	s.pingsSent.Add(1)
	conn, err := icmpx.ListenPacket("udp6", "::")
	if err != nil {
		hostFwdLog("v6 ListenPacket failed: %v", err)
		return
	}
	defer conn.Close()
	out := &icmpx.Message{
		Type: netipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmpx.Echo{ID: int(ident), Seq: int(seq), Data: payload},
	}
	// `nil` for the pseudo-header arg: the kernel computes the
	// real ICMPv6 checksum on outbound (it has to — we don't know
	// our actual source address until the socket binds).
	outBytes, err := out.Marshal(nil)
	if err != nil {
		return
	}
	if _, err := conn.WriteTo(outBytes, &net.UDPAddr{IP: dstIP}); err != nil {
		hostFwdLog("v6 WriteTo %v failed: %v", dstIP, err)
		return
	}
	if err := conn.SetReadDeadline(time.Now().Add(s.pingTimeout)); err != nil {
		return
	}
	rb := make([]byte, 1500)
	n, _, err := conn.ReadFrom(rb)
	if err != nil || n <= 0 {
		hostFwdLog("v6 ReadFrom %v failed: err=%v n=%d (no reply within %v)",
			dstIP, err, n, s.pingTimeout)
		return
	}
	s.pingsRpld.Add(1)
	msg, err := icmpx.ParseMessage(protoICMPv6, rb[:n])
	if err != nil {
		hostFwdLog("v6 ParseMessage failed: %v", err)
		return
	}
	if msg.Type != netipv6.ICMPTypeEchoReply {
		// Non-echo reply: Destination Unreachable, Packet Too Big,
		// Time Exceeded, or Parameter Problem.  PTB (RFC 8201) is
		// the load-bearing one for IPv6 PMTUD — the joiner's
		// kernel needs it to size further packets.  TODO V6.H2c:
		// translate the ICMPv6 error type into a synthesised
		// packet back to the joiner.  Silent-drop here means the
		// joiner can't discover path MTU through this forwarder,
		// which is mostly academic until joiners push fragments.
		return
	}
	echo, ok := msg.Body.(*icmpx.Echo)
	if !ok {
		return
	}
	// Same ident-preservation as v4: the kernel rewrote our ident
	// on the unprivileged socket, so use the joiner's original
	// value, not what we just read.
	s.injectEchoReplyV6(dstIP, srcIP, ident, uint16(echo.Seq), echo.Data)
}

// injectEchoReplyV6 — v6 sibling of [injectEchoReply].  Builds an
// IPv6+ICMPv6 echo-reply and pushes it into NIC1's channel via
// `WritePackets` (same anti-loop reasoning as v4: `InjectInbound`
// would trip gvisor's same-NIC drop).
func (s *hostForwarderState) injectEchoReplyV6(
	src, dst net.IP, ident, seq uint16, payload []byte,
) {
	if s.closed.Load() {
		return
	}
	pktBytes := buildIPv6ICMPEchoReply(src, dst, ident, seq, payload)
	buf := buffer.MakeWithData(pktBytes)
	pkt := gvstack.NewPacketBuffer(gvstack.PacketBufferOptions{Payload: buf})
	var pkts gvstack.PacketBufferList
	pkts.PushBack(pkt)
	s.inEp.WritePackets(pkts)
	pkt.DecRef()
	s.injectsOK.Add(1)
	hostFwdLog("injected v6 echo-reply %v -> %v ident=%d seq=%d (payload=%dB)",
		src, dst, ident, seq, len(payload))
}

// redirectViaTempAddressV6 — v6 sibling of [redirectViaTempAddress].
// Registers `dst` as a temp /128 local address on NIC1, then
// re-injects the v6 bytes through NIC1's channel.  gvisor's
// catchall TCP/UDP forwarders (registered at the transport layer
// in `listeners.go`) fire on the next pass since gvisor's TCP and
// UDP code are family-agnostic — the same handler accepts a v4 or
// v6 SYN/datagram.
func (s *hostForwarderState) redirectViaTempAddressV6(dst tcpip.Address, raw []byte) {
	s.ensureTempLocalAddressV6(dst)
	bytesCopy := make([]byte, len(raw))
	copy(bytesCopy, raw)
	buf := buffer.MakeWithData(bytesCopy)
	injectPkt := gvstack.NewPacketBuffer(gvstack.PacketBufferOptions{
		Payload: buf,
	})
	dstSlice := addrSliceLocal(dst)
	hostFwdLog("re-injecting %dB on NIC1 v6 (dst=%v, next-hdr=%d)",
		len(raw), net.IP(dstSlice), raw[6])
	s.inEp.InjectInbound(gvipv6.ProtocolNumber, injectPkt)
	injectPkt.DecRef()
}

func (s *hostForwarderState) ensureTempLocalAddressV6(addr tcpip.Address) {
	s.tempAddrMu.Lock()
	defer s.tempAddrMu.Unlock()
	if s.tempAddrs[addr] {
		return
	}
	s.tempAddrs[addr] = true
	protoAddr := tcpip.ProtocolAddress{
		Protocol: gvipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   addr,
			PrefixLen: 128,
		},
	}
	if err := s.stk.AddProtocolAddress(s.origNICID, protoAddr,
		gvstack.AddressProperties{Temporary: true}); err != nil {
		hostFwdLog("AddProtocolAddress v6 (%v) failed: %v", addr, err)
		return
	}
	s.tempAddrN.Add(1)
	hostFwdLog("registered temp local v6 addr %v", addr)
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

// buildIPv6ICMPEchoReply constructs a complete IPv6+ICMPv6 echo
// reply.  ICMPv6 (RFC 4443 §2.3) requires the checksum to cover
// the IPv6 pseudo-header (src/dst + length + next-header) in
// addition to the ICMPv6 message; this is the v6 sibling of
// [buildIPv4ICMPEchoReply], which only had to checksum the ICMP
// segment.
//
// `src` is the address the joiner pinged (the upstream that
// "replied"); `dst` is the joiner's own v6 address.  The IPv6
// header's PayloadLength is the ICMPv6 size (header + payload);
// HopLimit defaults to 64 — matches gvisor's default for outbound
// IPv6 + Linux's `net.ipv6.conf.all.hop_limit`.
func buildIPv6ICMPEchoReply(
	src, dst net.IP, ident, seq uint16, payload []byte,
) []byte {
	src16 := src.To16()
	dst16 := dst.To16()
	icmpLen := header.ICMPv6MinimumSize + len(payload)
	totalLen := header.IPv6MinimumSize + icmpLen
	pktBytes := make([]byte, totalLen)

	srcAddr := tcpip.AddrFromSlice(src16)
	dstAddr := tcpip.AddrFromSlice(dst16)

	ip := header.IPv6(pktBytes[:header.IPv6MinimumSize])
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(icmpLen),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           srcAddr,
		DstAddr:           dstAddr,
	})

	icmpStart := header.IPv6MinimumSize
	icmpBytes := pktBytes[icmpStart:]
	icmp := header.ICMPv6(icmpBytes[:header.ICMPv6MinimumSize])
	icmp.SetType(header.ICMPv6EchoReply)
	icmp.SetCode(0)
	icmp.SetIdent(ident)
	icmp.SetSequence(seq)
	copy(pktBytes[icmpStart+header.ICMPv6MinimumSize:], payload)
	// ICMPv6 checksum covers the IPv6 pseudo-header + ICMPv6
	// header + payload.  Compute over the parts excluding the
	// checksum field itself (gvisor's helper skips bytes 2-3 of
	// the header internally).
	icmp.SetChecksum(0)
	xsum := header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmp,
		Src:         srcAddr,
		Dst:         dstAddr,
		PayloadCsum: checksum.Checksum(payload, 0),
		PayloadLen:  len(payload),
	})
	icmp.SetChecksum(xsum)
	return pktBytes
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

// handleLocalICMPv6 — v6 sibling of [handleLocalICMP].  Fires for
// ICMPv6 packets whose dst is locally assigned on NIC1 (real-local
// `fd00::1` or a temp-local address registered by
// [redirectViaTempAddressV6]).
//
// gvisor's ICMPv6 module already auto-replies to echo requests
// for real-local addresses, so we forward only the temp-local
// case to the upstream-ping path.  Two notable v6 quirks:
//
//   - Real ICMPv6 traffic carries lots of non-echo messages
//     (router advertisements, neighbor solicits, multicast listener
//     discovery).  We filter to type 128 (EchoRequest) + code 0
//     so we don't accidentally synthesise a reply for an NDP packet.
//   - The transport handler's return value is unused by gvisor for
//     this code path; always false (sibling of v4).
func (s *hostForwarderState) handleLocalICMPv6(
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
	if len(icmpBytes) < header.ICMPv6MinimumSize {
		return false
	}
	icmpHdr := header.ICMPv6(icmpBytes)
	if icmpHdr.Type() != header.ICMPv6EchoRequest || icmpHdr.Code() != 0 {
		return false
	}
	ipBytes := pkt.NetworkHeader().Slice()
	if len(ipBytes) < header.IPv6MinimumSize {
		return false
	}
	ipHdr := header.IPv6(ipBytes)
	srcAddr := ipHdr.SourceAddress()
	dstAddr := ipHdr.DestinationAddress()
	srcIP := net.IP(addrSliceLocal(srcAddr))
	dstIP := net.IP(addrSliceLocal(dstAddr))
	if len(srcIP) != 16 || len(dstIP) != 16 {
		return false
	}
	ident := icmpHdr.Ident()
	seq := icmpHdr.Sequence()
	// AsRange().ToSlice(): see [TestEmptyPayloadToSliceVsToView]
	// for why ToView() is dangerous on empty payloads.
	payload := pkt.Data().AsRange().ToSlice()
	hostFwdLog("ICMPv6 echo (temp-local) %v -> %v ident=%d seq=%d payload=%dB",
		srcIP, dstIP, ident, seq, len(payload))
	s.pingWg.Add(1)
	go func() {
		defer s.pingWg.Done()
		s.dispatchPingV6(srcIP, dstIP, ident, seq, payload)
	}()
	return false
}

func (s *hostForwarderState) closeForwarder() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	s.stop()
	// V6.H2b: the shared pingWg covers both v4 and v6 ping
	// goroutines (dispatchPing + dispatchPingV6 both call
	// `s.pingWg.Add(1)/Done()`).  This Wait() therefore drains
	// in-flight pings of either family before NIC tear-down.
	s.pingWg.Wait()
	s.stk.SetRouteTable(s.origRoutes)
	s.stk.RemoveNIC(s.outNICID)
	// Forwarding-enable for ipv4/ipv6 is intentionally NOT reverted
	// here.  The whole stack dies with `nativeClose` (the bridge is
	// stack-scoped), so leaving forwarding=true is harmless: there
	// are no NICs left for traffic to route between.  Re-install
	// on the same bridge isn't a supported flow.
}
