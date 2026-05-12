// Diagnostic ICMPv4 ping helper. `wgbridgePingV4` sends one echo
// request from the bridge's gvisor stack and reports the RTT — used
// by the host-mode diagnostic UI and instrumented tests. Through-
// host ICMP forwarding (joiner → real internet) lives in
// host_forwarder.go.

package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"net"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// wgbridgePingV4 sends one ICMPv4 echo request from the bridge's
// netstack to [dest] and waits up to [timeoutMs] for the echo
// reply. Returns the round-trip time in microseconds on success.
//
// Negative returns:
//
//	-1 : invalid bridge handle
//	-2 : bridge is not host-mode (no netstack) OR netstack
//	 internal layout unexpected
//	-3 : address parse failed (must be a dotted IPv4)
//	-4 : NewEndpoint failed (stack out of memory etc.)
//	-5 : Connect failed (route missing? unusual)
//	-6 : timeout — no reply within [timeoutMs]
//	-7 : Write failed (the kernel/netstack refused the packet)
//	-8 : Read failed after Wait returned (rare, transient)
//
// The endpoint is closed before return regardless of outcome —
// no leak even on error path.
//
//export wgbridgePingV4
func wgbridgePingV4(handle C.int, destStr *C.char, destLen C.int,
	timeoutMs C.int) C.int {
	bs := lookupHandle(int32(handle))
	if bs == nil {
		return -1
	}
	if bs.tnet == nil {
		return -2
	}
	stk := extractStack(bs.tnet)
	if stk == nil {
		return -2
	}

	dest := C.GoStringN(destStr, C.int(destLen))
	ip4 := net.ParseIP(dest).To4()
	if ip4 == nil {
		return -3
	}
	fa := tcpip.FullAddress{
		Addr: tcpip.AddrFromSlice([]byte{ip4[0], ip4[1], ip4[2], ip4[3]}),
	}

	var wq waiter.Queue
	ep, tcpErr := stk.NewEndpoint(
		icmp.ProtocolNumber4, ipv4.ProtocolNumber, &wq)
	if tcpErr != nil {
		return -4
	}
	defer ep.Close()

	// Register for read-ready notifications BEFORE writing — the
	// reply could arrive before we get to the select if the
	// remote auto-replies on a fast loopback.
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventIn)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	if connErr := ep.Connect(fa); connErr != nil {
		return -5
	}

	// Build the echo request. Type 8, code 0; gvisor recomputes
	// the checksum on send so we leave it zero in the bytes we
	// pass. The ident (bytes 4-5) may be rewritten by gvisor to
	// match the endpoint's allocated value; that's fine — the
	// reply will arrive with the same rewritten ident and gvisor
	// will demux it to this endpoint.
	const echoRequest = header.ICMPv4Echo
	pkt := make([]byte, 8+32) // 8-byte header + 32-byte body
	pkt[0] = byte(echoRequest)
	pkt[1] = 0 // code
	pkt[2] = 0; pkt[3] = 0 // checksum (gvisor recomputes)
	pkt[4] = 0xAB; pkt[5] = 0xCD // ident (gvisor may rewrite)
	pkt[6] = 0; pkt[7] = 1 // sequence number
	// pkt[8..40] left as zeros (typical ping body)

	start := time.Now()
	var rdr bytes.Reader
	rdr.Reset(pkt)
	if _, werr := ep.Write(&rdr, tcpip.WriteOptions{}); werr != nil {
		return -7
	}

	select {
	case <-notifyCh:
		// fallthrough to read
	case <-time.After(time.Duration(timeoutMs) * time.Millisecond):
		return -6
	}

	var rbuf bytes.Buffer
	if _, rerr := ep.Read(&rbuf, tcpip.ReadOptions{}); rerr != nil {
		return -8
	}
	rtt := time.Since(start)
	us := rtt.Microseconds()
	if us < 0 {
		us = 0
	}
	if us > int64(^uint32(0)>>1) {
		us = int64(^uint32(0) >> 1)
	}
	return C.int(us)
}
