package main

import (
	"net/netip"
	"testing"
)

func TestParseInterfaceAddrsCsv_DualStack(t *testing.T) {
	v4, v6 := parseInterfaceAddrsCsv("10.50.0.3,2001:db8::3")
	if v4.String() != "10.50.0.3" {
		t.Errorf("v4 = %v, want 10.50.0.3", v4)
	}
	if v6.String() != "2001:db8::3" {
		t.Errorf("v6 = %v, want 2001:db8::3", v6)
	}
}

func TestParseInterfaceAddrsCsv_WhitespaceTolerated(t *testing.T) {
	v4, v6 := parseInterfaceAddrsCsv(" 10.50.0.3 , 2001:db8::3 ")
	if v4.String() != "10.50.0.3" || v6.String() != "2001:db8::3" {
		t.Errorf("got v4=%v v6=%v", v4, v6)
	}
}

func TestParseInterfaceAddrsCsv_StripsCIDR(t *testing.T) {
	v4, v6 := parseInterfaceAddrsCsv("10.50.0.3/32,2001:db8::3/128")
	if v4.String() != "10.50.0.3" || v6.String() != "2001:db8::3" {
		t.Errorf("got v4=%v v6=%v", v4, v6)
	}
}

func TestParseInterfaceAddrsCsv_EmptyAndInvalidSkipped(t *testing.T) {
	v4, v6 := parseInterfaceAddrsCsv(",not-an-ip,10.50.0.3,,")
	if v4.String() != "10.50.0.3" {
		t.Errorf("v4 = %v, want 10.50.0.3", v4)
	}
	if v6.IsValid() {
		t.Errorf("v6 = %v, want zero", v6)
	}
}

func TestParseInterfaceAddrsCsv_KeepsFirstWhenDuplicateFamily(t *testing.T) {
	// MVP can only NAT one address per family; assert we keep the
	// first one (caller logs a warning for subsequent drops).
	v4, v6 := parseInterfaceAddrsCsv("10.50.0.3,10.51.0.3,2001:db8::3,2001:db8::4")
	if v4 != netip.MustParseAddr("10.50.0.3") {
		t.Errorf("expected first IPv4 retained, got %v", v4)
	}
	if v6 != netip.MustParseAddr("2001:db8::3") {
		t.Errorf("expected first IPv6 retained, got %v", v6)
	}
}

func TestParseInterfaceAddrsCsv_EmptyInput(t *testing.T) {
	v4, v6 := parseInterfaceAddrsCsv("")
	if v4.IsValid() || v6.IsValid() {
		t.Errorf("empty input must yield zero addrs, got v4=%v v6=%v", v4, v6)
	}
}
