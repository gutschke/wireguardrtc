//go:build !android

package main

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	gvchannel "gvisor.dev/gvisor/pkg/tcpip/link/channel"
	gvipv4 "gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	gvstack "gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// TestRedirectViaTempAddressDeliversToUDPHandler mirrors the
// production install in `wgbridgeInstallHostForwarder`: two
// NICs, default route to NIC2, forwarding on, ICMPv4 transport
// handler bound. Then injects a UDP packet on NIC1 with a
// NON-LOCAL destination + drives a single iteration of
// `redirectViaTempAddress` — and asserts that the re-injected
// packet reaches a UDP transport handler.
//
// This is the test the production UDP-broken bug needs. If it
// fails, the bug is reproducible in pure Go (no wireguard-go,
// no Android). If it passes, the production bug lives somewhere
// between wireguard-go's decrypt path and gvisor's NIC1 receive
// — and we need to investigate that interface (likely the
// `PacketBuffer` layout that wireguard-go uses for InjectInbound
// vs the one we use after reading from NIC2's outbound queue).
func TestRedirectViaTempAddressDeliversToUDPHandler(t *testing.T) {
	stk := gvstack.New(gvstack.Options{
		NetworkProtocols: []gvstack.NetworkProtocolFactory{
			gvipv4.NewProtocol,
		},
		TransportProtocols: []gvstack.TransportProtocolFactory{
			udp.NewProtocol, tcp.NewProtocol, icmp.NewProtocol4,
		},
	})
	defer stk.Close()

	const (
		hostWGAddr = "10.99.0.1"
		joinerWGAddr = "10.99.0.2"
		externalDst = "1.1.1.1"
	)

	// NIC1 — wireguard-go's TUN-equivalent. We create the
	// channel endpoint ourselves; production extracts it from
	// netstack via reflection.
	inEp := gvchannel.New(2048, 1420, "")
	if err := stk.CreateNIC(1, inEp); err != nil {
		t.Fatalf("CreateNIC(1): %v", err)
	}
	hostAddr := tcpip.ProtocolAddress{
		Protocol: gvipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address: tcpip.AddrFromSlice(net.ParseIP(hostWGAddr).To4()),
			PrefixLen: 24,
		},
	}
	if err := stk.AddProtocolAddress(1, hostAddr, gvstack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(NIC1, %s): %v", hostWGAddr, err)
	}

	// NIC2 — the virtual outbound NIC the host_forwarder
	// installs. Mirror the install exactly.
	outEp := gvchannel.New(2048, 1420, "")
	if err := stk.CreateNIC(2, outEp); err != nil {
		t.Fatalf("CreateNIC(2): %v", err)
	}
	peerSubnet := tcpip.AddressWithPrefix{
		Address: tcpip.AddrFromSlice(net.ParseIP("10.99.0.0").To4()),
		PrefixLen: 24,
	}.Subnet()
	stk.SetRouteTable([]tcpip.Route{
		{Destination: peerSubnet, NIC: 1},
		{Destination: header.IPv4EmptySubnet, NIC: 2},
	})
	stk.SetForwardingDefaultAndAllNICs(gvipv4.ProtocolNumber, true)

	// Register a UDP transport handler we can introspect — same
	// pattern as `wgbridgeInstallUDPForwarder`, just without the
	// JNI dispatch.
	var udpFired atomic.Int32
	stk.SetTransportProtocolHandler(udp.ProtocolNumber,
		udp.NewForwarder(stk, func(r *udp.ForwarderRequest) {
			udpFired.Add(1)
			tid := r.ID()
			t.Logf("UDP handler fired: %v:%d -> %v:%d",
				tid.RemoteAddress, tid.RemotePort,
				tid.LocalAddress, tid.LocalPort)
		}).HandlePacket)

	// Build a real UDP datagram (Joiner 10.99.0.2:54321 →
	// External 1.1.1.1:53) — the exact shape ChromeOS sends for
	// a DNS query.
	const (
		sport = 54321
		dport = 53
	)
	payload := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// "google.com" wire format
		0x06, 'g', 'o', 'o', 'g', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01}
	udpLen := header.UDPMinimumSize + len(payload)
	totalLen := header.IPv4MinimumSize + udpLen
	pktBytes := make([]byte, totalLen)
	ip := header.IPv4(pktBytes[:header.IPv4MinimumSize])
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL: 64,
		Protocol: uint8(header.UDPProtocolNumber),
		SrcAddr: tcpip.AddrFromSlice(net.ParseIP(joinerWGAddr).To4()),
		DstAddr: tcpip.AddrFromSlice(net.ParseIP(externalDst).To4()),
	})
	ip.SetChecksum(0)
	ip.SetChecksum(^ip.CalculateChecksum())
	udpHdr := header.UDP(pktBytes[header.IPv4MinimumSize : header.IPv4MinimumSize+header.UDPMinimumSize])
	udpHdr.SetSourcePort(sport)
	udpHdr.SetDestinationPort(dport)
	udpHdr.SetLength(uint16(udpLen))
	copy(pktBytes[header.IPv4MinimumSize+header.UDPMinimumSize:], payload)
	// UDP checksum (pseudo-header + UDP + payload). Required —
	// gvisor's parse.UDP doesn't reject zero-checksum but Linux
	// kernels do, and we want the test to mirror reality.
	xsum := header.PseudoHeaderChecksum(header.UDPProtocolNumber,
		ip.SourceAddress(), ip.DestinationAddress(), uint16(udpLen))
	udpHdr.SetChecksum(0)
	udpHdr.SetChecksum(^udpHdr.CalculateChecksum(checksum.Checksum(payload, xsum)))

	// Step 1: Inject the UDP packet at NIC1 (wireguard-go would
	// do this after decrypt).
	buf := buffer.MakeWithData(pktBytes)
	pkt := gvstack.NewPacketBuffer(gvstack.PacketBufferOptions{Payload: buf})
	inEp.InjectInbound(gvipv4.ProtocolNumber, pkt)
	pkt.DecRef()

	// Step 2: The packet should hit gvisor's IP layer, see
	// dst=1.1.1.1 is non-local, and forward via NIC2. Read
	// it from NIC2's outbound queue.
	var forwarded *gvstack.PacketBuffer
	for i := 0; i < 200; i++ {
		if p := outEp.Read(); p != nil {
			forwarded = p
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if forwarded == nil {
		t.Fatalf("packet did not reach NIC2 outbound queue within 1s")
	}
	defer forwarded.DecRef()
	forwardedView := forwarded.ToView()
	if forwardedView == nil {
		t.Fatalf("forwarded.ToView() returned nil")
	}
	raw := forwardedView.AsSlice()
	defer forwardedView.Release()
	t.Logf("NIC2 outbound got %d bytes", len(raw))

	// Step 3: Mimic redirectViaTempAddress exactly.
	dstAddr := tcpip.AddrFromSlice(net.ParseIP(externalDst).To4())
	tempAddr := tcpip.ProtocolAddress{
		Protocol: gvipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: dstAddr, PrefixLen: 32},
	}
	if err := stk.AddProtocolAddress(1, tempAddr,
		gvstack.AddressProperties{Temporary: true}); err != nil {
		t.Fatalf("AddProtocolAddress(temp %s on NIC1): %v", externalDst, err)
	}
	bytesCopy := make([]byte, len(raw))
	copy(bytesCopy, raw)
	buf2 := buffer.MakeWithData(bytesCopy)
	injectPkt := gvstack.NewPacketBuffer(gvstack.PacketBufferOptions{Payload: buf2})
	inEp.InjectInbound(gvipv4.ProtocolNumber, injectPkt)
	injectPkt.DecRef()

	// Step 4: Give gvisor a moment, then assert the UDP handler
	// saw the packet.
	for i := 0; i < 50; i++ {
		if udpFired.Load() > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := udpFired.Load(); got == 0 {
		// Print address-table state to help diagnose.
		ainfo := stk.AllAddresses()
		t.Logf("stack addresses: %+v", ainfo)
		// Did gvisor route the re-injected packet to NIC2
		// again instead of delivering locally?
		if p := outEp.Read(); p != nil {
			t.Logf("re-injected packet bounced back to NIC2 outbound — temp-local lookup didn't take effect")
			p.DecRef()
		} else {
			t.Logf("re-injected packet didn't reach NIC2 — gvisor delivered it locally, but UDP handler still didn't fire")
		}
		t.Fatalf("UDP handler did NOT fire — production bug reproduced in pure Go")
	}
	t.Logf("UDP handler fired %d time(s) ✓", udpFired.Load())
}
