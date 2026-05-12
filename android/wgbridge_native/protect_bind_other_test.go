//go:build !android

// Sanity check for the non-Android fallback: newJoinerBind must
// return a conn.Bind so wgbridgeNewWithTunFd can construct a device
// during host-side `go test ./...`. The Android variant is exercised
// at runtime by the instrumented JoinerVpnService start path.

package main

import (
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
)

func TestNewJoinerBindFallbackReturnsAStdBind(t *testing.T) {
	b := newJoinerBind()
	if b == nil {
		t.Fatal("newJoinerBind returned nil")
	}
	// Behavioural assertion: ParseEndpoint must accept a literal
	// IPv4:port — same contract the production protect-aware bind
	// promises.
	ep, err := b.ParseEndpoint("203.0.113.5:51820")
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}
	if _, ok := ep.(*conn.StdNetEndpoint); !ok {
		t.Fatalf("expected *StdNetEndpoint, got %T", ep)
	}
}

// Regression for the "Send returns net.ErrClosed after a
// Close-then-Open cycle" bug found via the VC=9 device log:
// wireguard-go's BindUpdate calls Close() before Open() on the
// same Bind instance, so the bind must clear any "I was closed"
// flag inside Open or every subsequent Send short-circuits with
// `use of closed network connection`.
//
// The host-side fallback uses upstream StdNetBind, which gets this
// right; the test is therefore a contract check that any
// replacement Bind we drop in (including the Android-only
// protectingBind) must satisfy.
func TestBindCloseThenOpenIsUsable(t *testing.T) {
	b := newJoinerBind()
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("second Open after Close: %v", err)
	}
	if len(fns) == 0 {
		t.Fatal("second Open returned no ReceiveFuncs")
	}
	// Send must NOT report a stale ErrClosed. We send to a
	// guaranteed-unreachable address; the kernel may report
	// ENETUNREACH or accept the datagram and silently drop it.
	// Either is fine — the only thing we're pinning is that
	// "closed" wasn't sticky.
	loopback, _ := netip.ParseAddrPort("127.0.0.1:1")
	err = b.Send([][]byte{{0}}, &conn.StdNetEndpoint{AddrPort: loopback})
	if err != nil && err.Error() == "use of closed network connection" {
		t.Fatalf("Send returned stale ErrClosed: %v", err)
	}
	_ = b.Close()
}
