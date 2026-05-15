//go:build !android

package main

import (
	"strings"
	"testing"
)

// V6.H1 — parseLocalAddrs splits a comma-separated address string
// into a typed []netip.Addr, accepting both v4 and v6 entries.
// Pre-V6 the host bridge accepted exactly one address; this is the
// shim that lets the caller pass `10.99.0.1,fd00::1` for a
// dual-stack host bridge.  netstack.CreateNetTUN already supports
// a slice — V6.H1 is wire-in for the parse + pass.

func TestParseLocalAddrs_singleV4(t *testing.T) {
	addrs, err := parseLocalAddrs("10.99.0.1")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(addrs) != 1 || addrs[0].String() != "10.99.0.1" {
		t.Fatalf("got %v", addrs)
	}
	if !addrs[0].Is4() {
		t.Fatalf("expected v4: %v", addrs[0])
	}
}

func TestParseLocalAddrs_singleV6(t *testing.T) {
	addrs, err := parseLocalAddrs("fd00::1")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(addrs) != 1 || addrs[0].String() != "fd00::1" {
		t.Fatalf("got %v", addrs)
	}
	if !addrs[0].Is6() {
		t.Fatalf("expected v6: %v", addrs[0])
	}
}

func TestParseLocalAddrs_dualStackCommaSeparated(t *testing.T) {
	addrs, err := parseLocalAddrs("10.99.0.1,fd00::1")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(addrs) != 2 {
		t.Fatalf("expected 2 entries, got %d: %v", len(addrs), addrs)
	}
	if !addrs[0].Is4() || !addrs[1].Is6() {
		t.Fatalf("expected v4 then v6, got %v", addrs)
	}
}

func TestParseLocalAddrs_whitespaceAroundCommas(t *testing.T) {
	addrs, err := parseLocalAddrs(" 10.99.0.1 , fd00::1 ")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(addrs) != 2 {
		t.Fatalf("got %v", addrs)
	}
}

func TestParseLocalAddrs_emptyEntriesDropped(t *testing.T) {
	addrs, err := parseLocalAddrs("10.99.0.1,,fd00::1,")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(addrs) != 2 {
		t.Fatalf("expected 2, got %d: %v", len(addrs), addrs)
	}
}

func TestParseLocalAddrs_invalidRejected(t *testing.T) {
	_, err := parseLocalAddrs("not-an-ip")
	if err == nil {
		t.Fatalf("expected error for malformed input")
	}
	if !strings.Contains(err.Error(), "not-an-ip") {
		t.Fatalf("error should name the bad entry; got %v", err)
	}
}

func TestParseLocalAddrs_invalidMixedWithValidRejected(t *testing.T) {
	// One bad entry poisons the whole list — the host bridge
	// must not silently drop addresses (the operator typed
	// them; they expect both up).
	_, err := parseLocalAddrs("10.99.0.1,garbage")
	if err == nil {
		t.Fatalf("expected error for mixed valid/invalid input")
	}
}

func TestParseLocalAddrs_emptyStringRejected(t *testing.T) {
	_, err := parseLocalAddrs("")
	if err == nil {
		t.Fatalf("expected error for empty input")
	}
}

func TestParseLocalAddrs_whitespaceOnlyRejected(t *testing.T) {
	_, err := parseLocalAddrs("   ")
	if err == nil {
		t.Fatalf("expected error for whitespace-only input")
	}
}

func TestParseLocalAddrs_v6BracketsTolerated(t *testing.T) {
	// Some callers may pass `[fd00::1]` (bracketed); accept that
	// since wgbridgeNew is called with raw addresses, not endpoint
	// strings.  Bracketed form is the canonical way to disambiguate
	// from `addr:port`, and a robust parser strips them.
	addrs, err := parseLocalAddrs("[fd00::1]")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(addrs) != 1 || addrs[0].String() != "fd00::1" {
		t.Fatalf("got %v", addrs)
	}
}
