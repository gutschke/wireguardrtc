//go:build !android

package main

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// V6.H2 — `peer/dest` strings dispatched into Java via
// `wgbridge_dispatch_*` must be parseable by Kotlin's
// `splitHostPort`-style consumers.  Pre-V6.H2 the code did
// `fmt.Sprintf("%s:%d", tid.RemoteAddress, tid.RemotePort)` which
// for an IPv6 address produces `2001:db8::5:51820` — ambiguous
// (could be parsed as the host `2001:db8::5:51820` with no port,
// or as `2001:db8::5` with port `51820`).  Bracketed form
// `[2001:db8::5]:51820` is unambiguous and matches the joiner-side
// convention (`formatEndpoint`).
//
// `formatEndpointAddr(addr tcpip.Address, port uint16)` is the
// helper that picks the right form.

func TestFormatEndpointAddr_v4(t *testing.T) {
	got := formatEndpointAddr(tcpip.AddrFromSlice([]byte{203, 0, 113, 5}), 51820)
	if got != "203.0.113.5:51820" {
		t.Fatalf("v4: got %q", got)
	}
}

func TestFormatEndpointAddr_v6Brackets(t *testing.T) {
	// 2001:db8::5 as 16 bytes
	v6 := []byte{
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0x05,
	}
	got := formatEndpointAddr(tcpip.AddrFromSlice(v6), 51820)
	if got != "[2001:db8::5]:51820" {
		t.Fatalf("v6: got %q", got)
	}
}

func TestFormatEndpointAddr_v6Loopback(t *testing.T) {
	// ::1
	v6 := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	got := formatEndpointAddr(tcpip.AddrFromSlice(v6), 53)
	if got != "[::1]:53" {
		t.Fatalf("got %q", got)
	}
}

func TestFormatEndpointAddr_v4LoopbackRetainsForm(t *testing.T) {
	got := formatEndpointAddr(tcpip.AddrFromSlice([]byte{127, 0, 0, 1}), 53)
	if got != "127.0.0.1:53" {
		t.Fatalf("got %q", got)
	}
}

func TestFormatEndpointAddr_zeroPort(t *testing.T) {
	// Some flow types use port=0 (unconnected datagram) — must
	// still produce a parseable string.
	gotV4 := formatEndpointAddr(tcpip.AddrFromSlice([]byte{0, 0, 0, 0}), 0)
	if gotV4 != "0.0.0.0:0" {
		t.Fatalf("v4 zero: %q", gotV4)
	}
	v6Zero := make([]byte, 16)
	gotV6 := formatEndpointAddr(tcpip.AddrFromSlice(v6Zero), 0)
	if gotV6 != "[::]:0" {
		t.Fatalf("v6 zero: %q", gotV6)
	}
}

func TestFormatEndpointAddr_v4InV6MappedFormStaysBracketed(t *testing.T) {
	// ::ffff:203.0.113.5 — a v4-mapped v6 address.  We don't
	// special-case it; gvisor reports it as a 16-byte address
	// AND its `.String()` renders the trailing 4 bytes as pure
	// hex (`::ffff:cb00:7105`), not dotted-quad.  Bracketed v6
	// form is the right answer either way because the receiver
	// must parse it as v6 (the netstack gave us 16 bytes).
	v4mapped := []byte{
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0xff, 0xff, 203, 0, 113, 5,
	}
	got := formatEndpointAddr(tcpip.AddrFromSlice(v4mapped), 80)
	// gvisor canonicalises v4-mapped as hex segments; we pin
	// THAT here, not the more-readable dotted-quad sugar, since
	// any future gvisor change that prefers the latter would be
	// equally valid.  Both forms are bracketed.
	expected := "[::ffff:cb00:7105]:80"
	if got != expected {
		t.Fatalf("v4-mapped: got %q want %q (or %q)", got, expected, "[::ffff:203.0.113.5]:80")
	}
}
