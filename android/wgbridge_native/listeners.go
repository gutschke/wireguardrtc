// TCP / UDP listener exports.
//
// The host-mode bridge runs a gvisor netstack at the WG-side IP
// (e.g. 10.99.0.1). These exports let Kotlin open listening
// sockets ON THAT NETSTACK so when a joiner connects via WG to
// 10.99.0.1:80 the connection ends up at an `WgTcpAcceptor`
// callback on the JVM side. Without these the host can complete
// the WG handshake and respond to ICMP (gvisor handles that
// itself) but no userspace service is reachable.
//
// **Threading.** Each listenTCP spawns an accept-loop goroutine.
// Per accept, the goroutine calls back into Java via the
// C-side `wgbridge_dispatch_tcp_accept` (defined in
// `jni_android.c`). The dispatcher AttachCurrentThread's the
// goroutine to the JVM, calls the static `WgBridgeNative.onTcpAccept`
// method, then DetachCurrentThread's. Read / Write / Close calls
// originate from Java (Kotlin coroutines on the IO dispatcher),
// so they already have a JNIEnv — they go through the //export
// functions below synchronously.
//
// **UDP.** No accept loop — a single goroutine per listener reads
// datagrams in a tight ReadFrom loop and dispatches each one as a
// callback into Java. Outbound is `wgbridgeUDPSendTo` from Kotlin.
//
// **Lifecycle.** `wgbridgeCloseListener(id)` works for either
// TCP or UDP — the listener ID is unique across both maps.
// `wgbridgeTCPClose(connId)` closes one accepted TCP connection
// (does not affect the listener). When a bridge is closed
// ([wgbridgeClose]), the underlying netstack shuts down which
// causes all Accept / ReadFrom calls to error out; the accept
// loops exit and the JVM side gradually drops references via
// Close calls.

package main

/*
#include <stdlib.h>
#include "jni_android.h"
*/
import "C"

import (
	"fmt"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"unsafe"

	gvstack "gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// listenerState is the union of TCP / UDP listener and
// forwarder bookkeeping. We keep them in a single map keyed by
// listener ID so `wgbridgeCloseListener` doesn't need a separate
// kind argument — `kind` discriminates the union at lookup time.
type listenerState struct {
	kind listenerKind
	tcp *gonet.TCPListener // listenerKindTCP only
	udp *gonet.UDPConn // listenerKindUDP only
	hostFwd *hostForwarderState // listenerKindHostForwarder only
	bridgeID int32 // back-reference (informational)
	closed atomic.Bool
}

type listenerKind int

const (
	listenerKindTCP listenerKind = iota + 1
	listenerKindUDP
	// listenerKindTCPForwarder: a `tcp.NewForwarder` was
	// installed on the bridge's stack-level protocol handler.
	// No `tcp`/`udp` field is populated — closing it is best-
	// effort because gvisor doesn't expose an explicit
	// uninstall (we just let the bridge close drop the whole
	// stack).
	listenerKindTCPForwarder
	// listenerKindUDPForwarder: analog of TCPForwarder for UDP.
	// Per-flow state lives in [udpFlows]; closing the
	// forwarder iterates and closes each.
	listenerKindUDPForwarder
	// listenerKindHostForwarder: through-host packet forwarder
	// (Option B). See `host_forwarder.go` for the
	// architecture. Closing reverts the route table + removes
	// NIC2; per-flow temp local addresses are dropped when the
	// bridge is closed.
	listenerKindHostForwarder
)

// tcpConnState tracks one accepted TCP connection. Mapped to an
// int32 connection ID that Kotlin holds onto.
type tcpConnState struct {
	conn *gonet.TCPConn
	listenerID int32
	closed atomic.Bool
}

var (
	listenersMu sync.Mutex
	listeners = map[int32]*listenerState{}
	nextListID int32

	tcpConnsMu sync.Mutex
	tcpConns = map[int32]*tcpConnState{}
	nextConnID int32
)

// allocateListenerHandle stores [ls] under a fresh int32 and
// returns the ID. Wraps around at MaxInt32 (re-using IDs is
// only a problem if a stale ID is still being passed back — by
// the time that's an issue we have ~2B accepted connections, the
// process has bigger problems).
func allocateListenerHandle(ls *listenerState) int32 {
	listenersMu.Lock()
	defer listenersMu.Unlock()
	for {
		nextListID++
		if nextListID <= 0 {
			nextListID = 1
		}
		if _, taken := listeners[nextListID]; !taken {
			listeners[nextListID] = ls
			return nextListID
		}
	}
}

func lookupListener(id int32) *listenerState {
	listenersMu.Lock()
	defer listenersMu.Unlock()
	return listeners[id]
}

func freeListener(id int32) *listenerState {
	listenersMu.Lock()
	defer listenersMu.Unlock()
	ls := listeners[id]
	if ls != nil {
		delete(listeners, id)
	}
	return ls
}

func allocateTCPConnHandle(cs *tcpConnState) int32 {
	tcpConnsMu.Lock()
	defer tcpConnsMu.Unlock()
	for {
		nextConnID++
		if nextConnID <= 0 {
			nextConnID = 1
		}
		if _, taken := tcpConns[nextConnID]; !taken {
			tcpConns[nextConnID] = cs
			return nextConnID
		}
	}
}

func lookupTCPConn(id int32) *tcpConnState {
	tcpConnsMu.Lock()
	defer tcpConnsMu.Unlock()
	return tcpConns[id]
}

func freeTCPConn(id int32) *tcpConnState {
	tcpConnsMu.Lock()
	defer tcpConnsMu.Unlock()
	cs := tcpConns[id]
	if cs != nil {
		delete(tcpConns, id)
	}
	return cs
}

// ─────────────────────────────────────────────────────────────────
// TCP listener

// wgbridgeListenTCP opens a TCP listener on the bridge's netstack
// at 0.0.0.0:port. Returns:
//
//	> 0 : listener handle
//	 -1 : invalid bridge handle
//	 -2 : bridge is not host-mode (no netstack)
//	 -3 : ListenTCP failed (port collision / netstack error)
//
//export wgbridgeListenTCP
func wgbridgeListenTCP(handle C.int, port C.int) C.int {
	bs := lookupHandle(int32(handle))
	if bs == nil {
		return -1
	}
	if bs.tnet == nil {
		return -2
	}
	addr := &net.TCPAddr{IP: net.IPv4zero, Port: int(port)}
	ln, err := bs.tnet.ListenTCP(addr)
	if err != nil {
		return -3
	}
	ls := &listenerState{kind: listenerKindTCP, tcp: ln, bridgeID: int32(handle)}
	id := allocateListenerHandle(ls)
	go acceptLoopTCP(id, ls)
	return C.int(id)
}

func acceptLoopTCP(listenerID int32, ls *listenerState) {
	for {
		conn, err := ls.tcp.Accept()
		if err != nil {
			return // listener closed or unrecoverable error
		}
		if ls.closed.Load() {
			_ = conn.Close()
			return
		}
		tcpConn, ok := conn.(*gonet.TCPConn)
		if !ok {
			// Should never happen — gonet only returns TCPConn.
			_ = conn.Close()
			continue
		}
		cs := &tcpConnState{conn: tcpConn, listenerID: listenerID}
		connID := allocateTCPConnHandle(cs)
		peer := tcpConn.RemoteAddr().String()
		local := tcpConn.LocalAddr().String()
		cPeer := C.CString(peer)
		cLocal := C.CString(local)
		C.wgbridge_dispatch_tcp_accept(C.int(listenerID), C.int(connID), cPeer, cLocal)
		C.free(unsafe.Pointer(cPeer))
		C.free(unsafe.Pointer(cLocal))
	}
}

// wgbridgeTCPRead reads up to bufLen bytes from the connection
// into [buf]. Returns:
//
//	> 0 : bytes read
//	 0: EOF (peer closed write side)
//	 -1 : invalid connection handle OR transport error
//
// The buffer is provided by the JNI wrapper (pinned Java
// byte-array memory). The Go side never holds the pointer past
// the call's return, so the unsafe.Slice is safe.
//
//export wgbridgeTCPRead
func wgbridgeTCPRead(connHandle C.int, buf *C.char, bufLen C.int) C.int {
	cs := lookupTCPConn(int32(connHandle))
	if cs == nil {
		return -1
	}
	if cs.closed.Load() {
		return 0
	}
	if bufLen <= 0 {
		return 0
	}
	goBuf := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(bufLen))
	n, err := cs.conn.Read(goBuf)
	if err != nil {
		if n > 0 {
			return C.int(n)
		}
		// io.EOF and any other error both surface as 0 (EOF) or
		// -1 (transport). We don't preserve the distinction; the
		// JVM side handles both as "connection done."
		return 0
	}
	return C.int(n)
}

// wgbridgeTCPWrite writes up to bufLen bytes from [buf].
// Returns bytes written, or -1 on error.
//
//export wgbridgeTCPWrite
func wgbridgeTCPWrite(connHandle C.int, buf *C.char, bufLen C.int) C.int {
	cs := lookupTCPConn(int32(connHandle))
	if cs == nil {
		return -1
	}
	if cs.closed.Load() {
		return -1
	}
	if bufLen <= 0 {
		return 0
	}
	goBuf := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(bufLen))
	n, err := cs.conn.Write(goBuf)
	if err != nil {
		if n > 0 {
			return C.int(n)
		}
		return -1
	}
	return C.int(n)
}

// wgbridgeTCPClose tears down one accepted TCP connection.
// Idempotent.
//
//export wgbridgeTCPClose
func wgbridgeTCPClose(connHandle C.int) {
	cs := freeTCPConn(int32(connHandle))
	if cs == nil {
		return
	}
	cs.closed.Store(true)
	_ = cs.conn.Close()
}

// wgbridgeInstallTCPForwarder installs a `tcp.NewForwarder` on
// the bridge's gvisor stack as the TCP protocol handler. Every
// inbound SYN arriving on the netstack — regardless of
// destination port — fires the forwarder, which:
//
// 1. Creates a real endpoint (gvisor accepts the SYN).
// 2. Allocates a tcpConnState handle.
// 3. Dispatches `wgbridge_dispatch_tcp_forwarded_accept` with
// the connection's peer + original destination ("LocalAddr"
// from gvisor's POV — i.e., the address the joiner dialed).
//
// The Kotlin side maps the forwarder handle to a registered
// `TcpForwarderHandler` which opens an outbound OS socket + pumps
// bytes via `TcpFlowForwarder`.
//
// Returns:
//
//	> 0 : forwarder handle (use with wgbridgeCloseListener)
//	 -1 : invalid bridge handle
//	 -2 : bridge is not host-mode (no netstack)
//
// Multi-install on one bridge is supported by gvisor (the new
// SetTransportProtocolHandler replaces the previous), but
// shouldn't be needed — install once at bridge start.
//
//export wgbridgeInstallTCPForwarder
func wgbridgeInstallTCPForwarder(handle C.int) C.int {
	bs := lookupHandle(int32(handle))
	if bs == nil {
		return -1
	}
	if bs.tnet == nil {
		return -2
	}
	stk := extractStack(bs.tnet)
	if stk == nil {
		return -3 // unexpected: netstack internal layout changed
	}
	ls := &listenerState{kind: listenerKindTCPForwarder, bridgeID: int32(handle)}
	id := allocateListenerHandle(ls)
	hostFwdLog("TCP catchall installed (handle=%d listener=%d)", int(handle), id)
	fwd := tcp.NewForwarder(stk, 0 /* rcvWnd = default */, maxInFlightSYNs,
		func(r *tcp.ForwarderRequest) {
			// IMPORTANT: capture r.ID() BEFORE r.Complete() —
			// Complete sets r.segment to nil, after which
			// r.ID() panics with a nil-deref on r.segment.id.
			// (gvisor pkg/tcpip/transport/tcp/forwarder.go
			// Complete() line ~146 in v0.0.0-20250503; the
			// ID accessor at line 123 reads r.segment.id.)
			tid := r.ID()
			if ls.closed.Load() {
				r.Complete(true) // RST — we're being torn down
				return
			}
			var wq waiter.Queue
			ep, tcpErr := r.CreateEndpoint(&wq)
			if tcpErr != nil {
				r.Complete(true) // RST
				return
			}
			r.Complete(false)
			conn := gonet.NewTCPConn(&wq, ep)
			cs := &tcpConnState{conn: conn, listenerID: id}
			connID := allocateTCPConnHandle(cs)
			peer := fmt.Sprintf("%s:%d", tid.RemoteAddress, tid.RemotePort)
			dest := fmt.Sprintf("%s:%d", tid.LocalAddress, tid.LocalPort)
			cPeer := C.CString(peer)
			cDest := C.CString(dest)
			C.wgbridge_dispatch_tcp_forwarded_accept(
				C.int(id), C.int(connID), cPeer, cDest)
			C.free(unsafe.Pointer(cPeer))
			C.free(unsafe.Pointer(cDest))
		})
	stk.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	return C.int(id)
}

const maxInFlightSYNs = 1024

// wgbridgeInstallUDPForwarder installs a `udp.NewForwarder` on
// the bridge's gvisor stack as the UDP protocol handler. Every
// inbound UDP datagram for a NEW (peer, local-addr) 4-tuple
// fires the forwarder. Subsequent datagrams for the same
// 4-tuple route to the endpoint we register in the handler
// (gvisor's own per-endpoint demux).
//
// The forwarder allocates a UDP flow handle keyed on the
// 4-tuple + dispatches `wgbridge_dispatch_udp_forwarded_flow`
// with the peer / origDest + the first datagram's payload.
// The Kotlin handler opens an OS `DatagramSocket` to origDest
// (or whatever the EgressSelector remaps it to) and pumps
// datagrams bidirectionally. Replies arrive on the Kotlin
// side, which calls back into Go via [wgbridgeUDPFlowWrite] to
// inject them into the netstack toward the joiner.
//
// Returns:
//
//	> 0 : forwarder handle (close via wgbridgeCloseListener)
//	 -1 : invalid bridge handle
//	 -2 : bridge is not host-mode (no netstack)
//	 -3 : netstack internal layout unexpected
//
//export wgbridgeInstallUDPForwarder
func wgbridgeInstallUDPForwarder(handle C.int) C.int {
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
	ls := &listenerState{kind: listenerKindUDPForwarder, bridgeID: int32(handle)}
	id := allocateListenerHandle(ls)
	hostFwdLog("UDP catchall installed (handle=%d listener=%d)", int(handle), id)
	fwd := udp.NewForwarder(stk, func(r *udp.ForwarderRequest) {
		if ls.closed.Load() {
			return
		}
		tid := r.ID()
		hostFwdLog("UDP forwarder: new flow %v:%d -> %v:%d",
			tid.RemoteAddress, tid.RemotePort,
			tid.LocalAddress, tid.LocalPort)
		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		if tcpErr != nil {
			hostFwdLog("UDP forwarder: CreateEndpoint failed: %v", tcpErr)
			return
		}
		conn := gonet.NewUDPConn(&wq, ep)
		fs := &udpFlowState{conn: conn, forwarderID: id}
		flowID := allocateUDPFlowHandle(fs)
		peer := fmt.Sprintf("%s:%d", tid.RemoteAddress, tid.RemotePort)
		dest := fmt.Sprintf("%s:%d", tid.LocalAddress, tid.LocalPort)
		// Read the first datagram from the netstack-side conn
		// so we can hand its payload to Java with the
		// flow-open callback. Subsequent datagrams in this
		// flow are read by a background goroutine (started
		// below) and dispatched the same way.
		firstBuf := make([]byte, 65536)
		n, _, err := conn.ReadFrom(firstBuf)
		if err != nil || n <= 0 {
			hostFwdLog("UDP forwarder: ReadFrom (first) failed for %s: err=%v n=%d", peer, err, n)
			fs.close()
			freeUDPFlow(flowID)
			return
		}
		hostFwdLog("UDP forwarder: dispatching first-datagram %dB from %s -> %s", n, peer, dest)
		cPeer := C.CString(peer)
		cDest := C.CString(dest)
		cData := C.CBytes(firstBuf[:n])
		C.wgbridge_dispatch_udp_forwarded_flow(
			C.int(id), C.int(flowID), cPeer, cDest,
			(*C.char)(cData), C.int(n))
		C.free(unsafe.Pointer(cPeer))
		C.free(unsafe.Pointer(cDest))
		C.free(cData)
		// Background reader for additional datagrams on this
		// flow. Each one fires the *same* callback (the
		// Kotlin handler knows the flowID and just writes the
		// datagram to its OS DatagramSocket).
		go func() {
			buf := make([]byte, 65536)
			for {
				if fs.closed.Load() {
					return
				}
				m, _, err := conn.ReadFrom(buf)
				if err != nil || m <= 0 {
					return
				}
				cPeer := C.CString(peer)
				cDest := C.CString(dest)
				cData := C.CBytes(buf[:m])
				C.wgbridge_dispatch_udp_forwarded_flow(
					C.int(id), C.int(flowID), cPeer, cDest,
					(*C.char)(cData), C.int(m))
				C.free(unsafe.Pointer(cPeer))
				C.free(unsafe.Pointer(cDest))
				C.free(cData)
			}
		}()
	})
	stk.SetTransportProtocolHandler(udp.ProtocolNumber, fwd.HandlePacket)
	return C.int(id)
}

// wgbridgeUDPFlowWrite injects a reply datagram into the
// netstack-side conn so it flows back to the joiner. Returns
// bytes written or -1 on error.
//
//export wgbridgeUDPFlowWrite
func wgbridgeUDPFlowWrite(flowHandle C.int, buf *C.char, bufLen C.int) C.int {
	fs := lookupUDPFlow(int32(flowHandle))
	if fs == nil {
		return -1
	}
	if fs.closed.Load() {
		return -1
	}
	if bufLen <= 0 {
		return 0
	}
	goBuf := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(bufLen))
	n, err := fs.conn.Write(goBuf)
	if err != nil {
		if n > 0 {
			return C.int(n)
		}
		return -1
	}
	return C.int(n)
}

// wgbridgeUDPFlowClose closes one UDP flow. Idempotent. The
// Kotlin side calls this when its idle timer expires or on bridge
// shutdown.
//
//export wgbridgeUDPFlowClose
func wgbridgeUDPFlowClose(flowHandle C.int) {
	fs := freeUDPFlow(int32(flowHandle))
	if fs != nil {
		fs.close()
	}
}

// udpFlowState tracks one (peer, dest) UDP flow's netstack-side
// endpoint. Per-flow OS DatagramSocket lives on the Kotlin side.
type udpFlowState struct {
	conn *gonet.UDPConn
	forwarderID int32
	closed atomic.Bool
}

func (fs *udpFlowState) close() {
	if !fs.closed.CompareAndSwap(false, true) {
		return
	}
	_ = fs.conn.Close()
}

var (
	udpFlowsMu sync.Mutex
	udpFlows = map[int32]*udpFlowState{}
	nextUDPFlowID int32
)

func allocateUDPFlowHandle(fs *udpFlowState) int32 {
	udpFlowsMu.Lock()
	defer udpFlowsMu.Unlock()
	for {
		nextUDPFlowID++
		if nextUDPFlowID <= 0 {
			nextUDPFlowID = 1
		}
		if _, taken := udpFlows[nextUDPFlowID]; !taken {
			udpFlows[nextUDPFlowID] = fs
			return nextUDPFlowID
		}
	}
}

func lookupUDPFlow(id int32) *udpFlowState {
	udpFlowsMu.Lock()
	defer udpFlowsMu.Unlock()
	return udpFlows[id]
}

func freeUDPFlow(id int32) *udpFlowState {
	udpFlowsMu.Lock()
	defer udpFlowsMu.Unlock()
	fs := udpFlows[id]
	if fs != nil {
		delete(udpFlows, id)
	}
	return fs
}

// extractStack reaches into a `*netstack.Net` and returns its
// underlying `*stack.Stack`. netstack doesn't export an
// accessor (the `stack` field is unexported), so we use
// reflection. The field name has been stable in
// `golang.zx2c4.com/wireguard/tun/netstack` for years; if a
// future upgrade renames it, all forwarder installs will fail
// with a clear error from this function (rather than a silent
// nil-stack panic later).
//
// Returns nil if the field can't be located or has the wrong
// type — caller treats that as an unrecoverable bug + refuses
// to install the forwarder.
func extractStack(n *netstack.Net) *gvstack.Stack {
	v := reflect.ValueOf(n).Elem()
	f := v.FieldByName("stack")
	if !f.IsValid() {
		return nil
	}
	// Field is unexported; reflect.Value.Interface() would
	// panic. unsafe.Pointer on the address gives us the
	// pointer value bypassing the export check.
	if f.Kind() != reflect.Ptr {
		return nil
	}
	ptr := unsafe.Pointer(f.UnsafeAddr())
	return *(**gvstack.Stack)(ptr)
}

// wgbridgeDialTCP opens an outbound TCP connection THROUGH the
// host-mode bridge's netstack to [dest] (in "host:port" form).
// Returns a connection handle compatible with [wgbridgeTCPRead] /
// [wgbridgeTCPWrite] / [wgbridgeTCPClose].
//
// Primarily a test affordance — production code rarely needs to
// dial OUT of a host bridge (the host's role is to be dialled
// into, not to initiate connections inside the WG tunnel).
// Negative returns:
//
//	-1 : invalid bridge handle
//	-2 : bridge is not host-mode (no netstack)
//	-3 : address parse failed
//	-4 : DialTCP failed (peer unreachable, route missing, etc.)
//
//export wgbridgeDialTCP
func wgbridgeDialTCP(handle C.int, destStr *C.char, destLen C.long) C.int {
	bs := lookupHandle(int32(handle))
	if bs == nil {
		return -1
	}
	if bs.tnet == nil {
		return -2
	}
	dest := goStringToGo(destStr, destLen)
	addr, err := net.ResolveTCPAddr("tcp", dest)
	if err != nil {
		return -3
	}
	tc, err := bs.tnet.DialTCP(addr)
	if err != nil {
		return -4
	}
	cs := &tcpConnState{conn: tc, listenerID: 0 /* not listener-owned */}
	connID := allocateTCPConnHandle(cs)
	return C.int(connID)
}

// ─────────────────────────────────────────────────────────────────
// UDP listener

// wgbridgeListenUDP opens a UDP socket on the bridge's netstack
// at 0.0.0.0:port. Returns the listener handle (see ListenTCP
// for error codes).
//
//export wgbridgeListenUDP
func wgbridgeListenUDP(handle C.int, port C.int) C.int {
	bs := lookupHandle(int32(handle))
	if bs == nil {
		return -1
	}
	if bs.tnet == nil {
		return -2
	}
	addr := &net.UDPAddr{IP: net.IPv4zero, Port: int(port)}
	uc, err := bs.tnet.ListenUDP(addr)
	if err != nil {
		return -3
	}
	ls := &listenerState{kind: listenerKindUDP, udp: uc, bridgeID: int32(handle)}
	id := allocateListenerHandle(ls)
	go recvLoopUDP(id, ls)
	return C.int(id)
}

func recvLoopUDP(listenerID int32, ls *listenerState) {
	buf := make([]byte, 65536)
	for {
		n, fromAddr, err := ls.udp.ReadFrom(buf)
		if err != nil {
			return
		}
		if ls.closed.Load() {
			return
		}
		peer := fromAddr.String()
		local := ls.udp.LocalAddr().String()
		cPeer := C.CString(peer)
		cLocal := C.CString(local)
		cData := C.CBytes(buf[:n])
		C.wgbridge_dispatch_udp_datagram(
			C.int(listenerID), cPeer, cLocal,
			(*C.char)(cData), C.int(n))
		C.free(unsafe.Pointer(cPeer))
		C.free(unsafe.Pointer(cLocal))
		C.free(cData)
	}
}

// wgbridgeUDPSendTo sends a UDP datagram via [listenerHandle] to
// [peerAddr]. Returns:
//
//	bytes written (>=0)
//	-1 on error / invalid handle
//
//export wgbridgeUDPSendTo
func wgbridgeUDPSendTo(listenerHandle C.int,
	peerAddrStr *C.char, peerAddrLen C.long,
	buf *C.char, bufLen C.int) C.int {
	ls := lookupListener(int32(listenerHandle))
	if ls == nil || ls.kind != listenerKindUDP {
		return -1
	}
	if ls.closed.Load() {
		return -1
	}
	peer := goStringToGo(peerAddrStr, peerAddrLen)
	addr, err := net.ResolveUDPAddr("udp", peer)
	if err != nil {
		return -1
	}
	if bufLen <= 0 {
		return 0
	}
	goBuf := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(bufLen))
	n, err := ls.udp.WriteTo(goBuf, addr)
	if err != nil {
		if n > 0 {
			return C.int(n)
		}
		return -1
	}
	return C.int(n)
}

// ─────────────────────────────────────────────────────────────────
// Common close

// wgbridgeCloseListener closes a TCP or UDP listener and stops
// its accept / recv loop. Already-accepted TCP connections stay
// open — close them individually via wgbridgeTCPClose.
//
//export wgbridgeCloseListener
func wgbridgeCloseListener(listenerHandle C.int) {
	ls := freeListener(int32(listenerHandle))
	if ls == nil {
		return
	}
	ls.closed.Store(true)
	switch ls.kind {
	case listenerKindTCP:
		_ = ls.tcp.Close()
	case listenerKindUDP:
		_ = ls.udp.Close()
	case listenerKindHostForwarder:
		if ls.hostFwd != nil {
			ls.hostFwd.closeForwarder()
		}
	}
}
