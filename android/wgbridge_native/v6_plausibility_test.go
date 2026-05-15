//go:build !android

package main

// V6.PL — plausibility tests for IPv6 ULA on the host's gvisor
// netstack.
//
// Question being answered:  the userspace-NAT architecture
// (gvisor netstack inside the WG bridge; per-flow OS sockets for
// egress) is family-agnostic by design — does that hold up when
// the WG-side address is an IPv6 ULA (e.g. `fd00::1`)?
//
// What we verify here at the lowest layer (pure Go, no
// emulator, no JNI):
//
//   1. `netstack.CreateNetTUN` accepts a v6 ULA in the address
//      list AND registers an IPv6 NIC at that address.
//   2. The same `*netstack.Net` can `ListenTCP` on the v6 address
//      and accept a connection dialed via `DialTCP`.
//   3. Mixed-family dial — the same stack handles v4 + v6
//      listeners simultaneously without cross-talk.
//
// If these pass, the gvisor netstack handles v6 ULA correctly.
// V6.PL Layer 2 (catchall forwarder with crafted v6 packet) and
// Layer 3 (real WG handshake + ping through the bridge from an
// unshare-sandboxed Linux WG client) live in separate test
// harnesses.
//
// Why ULA might NOT route correctly: a ULA source address can't
// reach the global v6 internet on its own.  But in the wgrtc
// architecture the host's catchall forwarder receives the inner
// packet at the gvisor netstack, then opens an OS socket from
// the host's interface (which DOES have a GUA or v4) toward the
// destination.  The ULA never appears on the wire outside the
// WG tunnel — same trick the existing v4 setup uses to route
// `10.99.0.2` joiners to public IPs.

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// TestV6PL_NetstackAcceptsULA confirms CreateNetTUN succeeds
// with a v6 ULA as the sole local address.  Pre-V6.H1 this would
// have errored at the cgo layer because the caller passed only
// a single string; that was fixed by `parseLocalAddrs`.
func TestV6PL_NetstackAcceptsULA(t *testing.T) {
	addr := netip.MustParseAddr("fd00::1")
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, nil, 1420)
	if err != nil {
		t.Fatalf("CreateNetTUN(fd00::1): %v", err)
	}
	defer tunDev.Close()
	if tnet == nil {
		t.Fatalf("CreateNetTUN returned nil *Net")
	}
}

// TestV6PL_NetstackAcceptsDualStack — the dual-stack case that
// V6.H1 wired up.  Both v4 + v6 addresses must register cleanly.
func TestV6PL_NetstackAcceptsDualStack(t *testing.T) {
	v4 := netip.MustParseAddr("10.99.0.1")
	v6 := netip.MustParseAddr("fd00::1")
	tunDev, _, err := netstack.CreateNetTUN([]netip.Addr{v4, v6}, nil, 1420)
	if err != nil {
		t.Fatalf("CreateNetTUN(v4,v6): %v", err)
	}
	defer tunDev.Close()
}

// TestV6PL_ListenAndDialOnULA — the load-bearing plausibility
// test.  A goroutine listens on `[fd00::1]:8080` via the gvisor
// stack; the main test dials it from the *same* stack
// (`HandleLocal: true` is set in CreateNetTUN, so same-stack
// loopback works without going through the channel endpoint).
// If gvisor handles ULA correctly through its TCP stack, bytes
// flow.  If routing breaks (the prefix is somehow not seen as
// local), the dial fails or the listen never receives the SYN.
func TestV6PL_ListenAndDialOnULA(t *testing.T) {
	addr := netip.MustParseAddr("fd00::1")
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, nil, 1420)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	defer tunDev.Close()

	ln, err := tnet.ListenTCP(&net.TCPAddr{
		IP:   net.ParseIP("fd00::1"),
		Port: 8080,
	})
	if err != nil {
		t.Fatalf("ListenTCP fd00::1:8080: %v", err)
	}
	defer ln.Close()

	want := []byte("hello v6")
	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- fmt.Errorf("Accept: %w", err)
			return
		}
		defer conn.Close()
		buf := make([]byte, 16)
		n, err := conn.Read(buf)
		if err != nil {
			done <- fmt.Errorf("Read: %w", err)
			return
		}
		if !bytes.Equal(buf[:n], want) {
			done <- fmt.Errorf("got %q want %q", buf[:n], want)
			return
		}
		// Echo back so the dialer's Read also confirms.
		if _, err := conn.Write(want); err != nil {
			done <- fmt.Errorf("Write: %w", err)
			return
		}
		done <- nil
	}()

	conn, err := tnet.DialTCP(&net.TCPAddr{
		IP:   net.ParseIP("fd00::1"),
		Port: 8080,
	})
	if err != nil {
		t.Fatalf("DialTCP [fd00::1]:8080: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("client Write: %v", err)
	}
	buf := make([]byte, 16)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("client Read: %v", err)
	}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("client read %q want %q", buf[:n], want)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("server side: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("server side timed out")
	}
}

// TestV6PL_DualStackBothFamiliesWork — same as above but with
// a dual-stack netstack.  Pin that registering a v6 NIC alongside
// a v4 NIC doesn't break v4 listen (regression against any
// future stack-config change that drops one family).
func TestV6PL_DualStackBothFamiliesWork(t *testing.T) {
	v4 := netip.MustParseAddr("10.99.0.1")
	v6 := netip.MustParseAddr("fd00::1")
	tunDev, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{v4, v6}, nil, 1420)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	defer tunDev.Close()

	// v4 listen + dial
	ln4, err := tnet.ListenTCP(&net.TCPAddr{IP: net.IPv4(10, 99, 0, 1), Port: 4000})
	if err != nil {
		t.Fatalf("v4 ListenTCP: %v", err)
	}
	defer ln4.Close()

	// v6 listen + dial
	ln6, err := tnet.ListenTCP(&net.TCPAddr{IP: net.ParseIP("fd00::1"), Port: 4000})
	if err != nil {
		t.Fatalf("v6 ListenTCP: %v", err)
	}
	defer ln6.Close()

	// Dial v4
	c4, err := tnet.DialTCP(&net.TCPAddr{IP: net.IPv4(10, 99, 0, 1), Port: 4000})
	if err != nil {
		t.Fatalf("v4 DialTCP: %v", err)
	}
	c4.Close()
	// Accept the v4 dial so the listener loop closes cleanly.
	acc4, err := ln4.Accept()
	if err != nil {
		t.Fatalf("v4 Accept: %v", err)
	}
	acc4.Close()

	// Dial v6
	c6, err := tnet.DialTCP(&net.TCPAddr{IP: net.ParseIP("fd00::1"), Port: 4000})
	if err != nil {
		t.Fatalf("v6 DialTCP: %v", err)
	}
	c6.Close()
	acc6, err := ln6.Accept()
	if err != nil {
		t.Fatalf("v6 Accept: %v", err)
	}
	acc6.Close()
}

// TestV6PL_UlaListenSpecificAddress — `wgbridgeListenTCP` uses
// `net.IPv4zero` (= `0.0.0.0`) as the bind address, which works
// for v4 because gvisor accepts the v4 unspecified as a wildcard.
// For v6 the same trick (`net.IPv6unspecified` = `[::]`) DOES
// NOT work — gvisor returns `bad local address`.  But that
// doesn't matter in production because the catchall TCP /
// UDP forwarder uses `tcp.NewForwarder` / `udp.NewForwarder`
// at the *transport* protocol level (not a port-bound listener),
// and the forwarder fires on every inbound SYN/datagram
// regardless of family.  The per-port `wgbridgeListenTCP` path
// is only used by tests; it would need v6-specific bind logic
// if we ever wanted to extend it.  Pin the v6-specific-address
// bind case here so the *test* path also works.
func TestV6PL_UlaListenSpecificAddress(t *testing.T) {
	addr := netip.MustParseAddr("fd00::1")
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, nil, 1420)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	defer tunDev.Close()

	ln, err := tnet.ListenTCP(&net.TCPAddr{IP: net.ParseIP("fd00::1"), Port: 6000})
	if err != nil {
		t.Fatalf("ListenTCP fd00::1:6000: %v", err)
	}
	defer ln.Close()

	conn, err := tnet.DialTCP(&net.TCPAddr{IP: net.ParseIP("fd00::1"), Port: 6000})
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer conn.Close()
	acc, err := ln.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	acc.Close()
}

// TestV6PL_GvisorRefusesV6Wildcard — DOCUMENTATION test pinning
// the gvisor limitation: `[::]` as bind address returns
// "bad local address" because gvisor treats the unspecified v6
// address differently from `0.0.0.0` (which IS accepted as a
// v4 wildcard).  If a future gvisor release fixed this, the
// test would start passing → tells us the limitation is gone
// and we can drop the family-specific bind hack from any
// future v6 `wgbridgeListenTCP` extension.
func TestV6PL_GvisorRefusesV6Wildcard(t *testing.T) {
	addr := netip.MustParseAddr("fd00::1")
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, nil, 1420)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	defer tunDev.Close()

	_, err = tnet.ListenTCP(&net.TCPAddr{IP: net.IPv6unspecified, Port: 6001})
	if err == nil {
		t.Logf("UNEXPECTED PASS: gvisor now accepts [::] wildcard; " +
			"can simplify any future v6 wgbridgeListenTCP extension.")
		// Don't fail — this would be a *welcome* upgrade.
		return
	}
	// Specifically check that it's the bind-address rejection, not
	// some unrelated error.
	if !contains(err.Error(), "bad local address") {
		t.Fatalf("expected `bad local address`, got %v", err)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) &&
		indexOf(haystack, needle) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// TestV6PL_CatchallForwarderFiresOnV6 — Layer 2: install the
// same `tcp.NewForwarder` that production code uses, dial it
// from a v6 client (same stack), verify the forwarder's callback
// fires AND receives a v6 RemoteAddress that `formatEndpointAddr`
// would correctly bracket.
//
// This is the layer-2 plausibility argument: gvisor's transport-
// level forwarder is family-agnostic.  The same handler that
// today fires on v4 SYNs will fire on v6 SYNs once the v6 NIC
// is registered (V6.H1) — no v6-specific forwarder code needed.
func TestV6PL_CatchallForwarderFiresOnV6(t *testing.T) {
	addr := netip.MustParseAddr("fd00::1")
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, nil, 1420)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	defer tunDev.Close()
	stk := extractStack(tnet)
	if stk == nil {
		t.Fatalf("extractStack returned nil — netstack internal layout changed?")
	}

	var fired atomic.Int32
	var seenRemote tcpip.Address
	var seenLocal tcpip.Address
	var seenRemotePort uint16
	var seenLocalPort uint16

	fwd := tcp.NewForwarder(stk, 0, maxInFlightSYNs, func(r *tcp.ForwarderRequest) {
		tid := r.ID()
		seenRemote = tid.RemoteAddress
		seenLocal = tid.LocalAddress
		seenRemotePort = tid.RemotePort
		seenLocalPort = tid.LocalPort
		var wq waiter.Queue
		ep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		fired.Add(1)
		// Close immediately — we don't care about bytes, just
		// that the forwarder saw the connection with the right
		// address family.
		ep.Close()
	})
	stk.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)

	// Dial via the *same* stack — since HandleLocal is true, the
	// SYN goes to the forwarder callback before the local listen
	// path even sees it.  No need to install a separate listener.
	conn, err := tnet.DialTCP(&net.TCPAddr{IP: net.ParseIP("fd00::1"), Port: 7000})
	if err != nil {
		t.Fatalf("DialTCP fd00::1: %v", err)
	}
	conn.Close()

	// Allow the forwarder's goroutine to run.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && fired.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if fired.Load() == 0 {
		t.Fatalf("forwarder callback never fired on v6 SYN")
	}

	// Verify the addresses gvisor delivered are 16 bytes (v6
	// family).  formatEndpointAddr brackets these correctly per
	// V6.H2; the test above already pins the formatter.
	if seenRemote.Len() != 16 {
		t.Fatalf("expected v6 RemoteAddress (16 bytes), got %d bytes", seenRemote.Len())
	}
	if seenLocal.Len() != 16 {
		t.Fatalf("expected v6 LocalAddress (16 bytes), got %d bytes", seenLocal.Len())
	}
	if seenLocalPort != 7000 {
		t.Fatalf("LocalPort=%d, want 7000", seenLocalPort)
	}
	_ = seenRemotePort // ephemeral, just sanity that it parsed

	// And the V6.H2 formatter must produce a bracket-parseable
	// string for these.  Inline the bracket so this stays a Layer-
	// 2 test (doesn't depend on listeners.go's formatEndpointAddr
	// implementation directly — but uses the same convention).
	got := formatEndpointAddr(seenLocal, seenLocalPort)
	want := fmt.Sprintf("[%s]:%d", seenLocal.String(), seenLocalPort)
	if got != want {
		t.Fatalf("formatEndpointAddr inconsistency: got %q want %q", got, want)
	}
}

// TestV6PL_CatchallForwarderFiresOnV4AfterDualStackRegistration —
// regression-pin: registering a v6 NIC alongside v4 doesn't
// break the v4 catchall path.
func TestV6PL_CatchallForwarderFiresOnV4AfterDualStackRegistration(t *testing.T) {
	v4 := netip.MustParseAddr("10.99.0.1")
	v6 := netip.MustParseAddr("fd00::1")
	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{v4, v6}, nil, 1420)
	if err != nil {
		t.Fatalf("CreateNetTUN: %v", err)
	}
	defer tunDev.Close()
	stk := extractStack(tnet)

	var fired atomic.Int32
	var seenRemote tcpip.Address
	fwd := tcp.NewForwarder(stk, 0, maxInFlightSYNs, func(r *tcp.ForwarderRequest) {
		tid := r.ID()
		seenRemote = tid.RemoteAddress
		var wq waiter.Queue
		if ep, terr := r.CreateEndpoint(&wq); terr == nil {
			r.Complete(false)
			fired.Add(1)
			ep.Close()
		} else {
			r.Complete(true)
		}
	})
	stk.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)

	conn, err := tnet.DialTCP(&net.TCPAddr{IP: net.IPv4(10, 99, 0, 1), Port: 7001})
	if err != nil {
		t.Fatalf("v4 DialTCP: %v", err)
	}
	conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && fired.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if fired.Load() == 0 {
		t.Fatalf("v4 forwarder callback never fired (regression — v6 registration broke v4)")
	}
	if seenRemote.Len() != 4 {
		t.Fatalf("expected v4 (4-byte) RemoteAddress, got %d bytes", seenRemote.Len())
	}
}
