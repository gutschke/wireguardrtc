// Joiner-N's "shared netstack" — one gvisor stack between the
// kernel TUN (NIC0) and N wireguard-go joiner bridges (NIC1..NICk).
// See `docs/cascade-n-design.md` §Primary architecture for the
// packet flow.
//
// This file delivers the Go-side scaffolding: the
// `sharedStackState` data structure, a handle map keyed off the
// same int32 space the existing `bridges` map uses, and the
// internal Go API for creating / closing the stack and attaching /
// detaching channel-endpoint NICs with route programming.
//
// The follow-on `D4.J2` file plugs the kernel TUN read/write
// pump into NIC0 and exposes a way to open a wireguard-go bridge
// that's wired to a per-NIC channel endpoint on this stack.
//
// **Why a separate handle namespace.** The existing `bridges`
// map (`api.go`) is keyed by handle and holds wireguard-go
// devices. Shared stacks are a different kind of object —
// they own *multiple* bridges plus link endpoints — so keeping
// them in their own map (`sharedStacks`) avoids the
// per-handle-shape branching that would otherwise creep into
// every `lookupHandle` call.

package main

import "C"

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// sharedStackState owns one gvisor stack with N+1 channel-endpoint
// NICs. NIC 1 (`reservedKernelTunNicID`) is reserved for the
// kernel-TUN side (attached via `attachKernelTunNic` / `D4.J2`);
// NIC 2..k (`firstJoinerNicID` and up) hold wireguard-go joiner
// bridges. gvisor reserves NIC ID 0 as invalid, so the first
// usable ID is 1.
//
// All exported methods are safe for concurrent calls. Internal
// `endpoints` map is guarded by `mu`; the gvisor `Stack` itself
// is thread-safe.
type sharedStackState struct {
	stack *stack.Stack

	mu sync.Mutex
	// endpoints maps NIC ID → its link endpoint. Used by D4.J2 to
	// hand a per-NIC channel.Endpoint to wireguard-go (the joiner
	// reads/writes packets via this endpoint).
	endpoints map[tcpip.NICID]*channel.Endpoint
	// nextNicID is monotonic — NIC IDs are never reused even after
	// detach so any stale route references log loudly instead of
	// silently rebinding to a different joiner.
	nextNicID atomic.Int32

	// pumpHandle owns the kernel-TUN read/write goroutines once
	// `attachKernelTunPump` has been called. Stored here so
	// [close] is a one-stop teardown for the whole stack
	// (D4.J3 — the JNI surface only exchanges stack handles, not
	// per-pump handles).
	pumpHandle *kernelTunPumpHandle

	// mtu is the link-layer MTU advertised to each NIC. We keep it
	// stack-wide because gvisor's PMTUD machinery wants every NIC
	// of a routing path to agree. For joiner-N the floor is min(
	// per-joiner MTU), enforced at the caller layer.
	mtu uint32
}

const (
	// reservedKernelTunNicID — NIC 1 is reserved for the kernel-TUN
	// side (gvisor reserves NIC ID 0 as invalid; 1 is the first
	// usable). Allocated by `attachKernelTunNic` in this file +
	// pump in `joiner_n_pump.go`; we just declare the constant
	// here so every reference uses the same value.
	reservedKernelTunNicID tcpip.NICID = 1

	// firstJoinerNicID — joiner NICs start at 2 so NIC 1 stays
	// recognisable as "kernel TUN".
	firstJoinerNicID tcpip.NICID = 2
)

var (
	sharedStacksMu sync.Mutex
	sharedStacks   = map[int32]*sharedStackState{}
	nextStackID    int32 // monotonic; never reused
)

// allocateSharedStackHandle assigns a fresh int32 to [s] and
// stores it in [sharedStacks]. Mirrors `allocateHandle` from
// `api.go` but uses its own counter so the namespaces don't
// collide.
func allocateSharedStackHandle(s *sharedStackState) int32 {
	sharedStacksMu.Lock()
	defer sharedStacksMu.Unlock()
	for {
		nextStackID++
		if nextStackID < 1 {
			nextStackID = 1
		}
		if _, taken := sharedStacks[nextStackID]; taken {
			continue
		}
		sharedStacks[nextStackID] = s
		return nextStackID
	}
}

// lookupSharedStack returns the state for [handle], or nil if
// the handle is unknown.
func lookupSharedStack(handle int32) *sharedStackState {
	sharedStacksMu.Lock()
	defer sharedStacksMu.Unlock()
	return sharedStacks[handle]
}

// freeSharedStack removes [handle] from the map and returns the
// state. Caller is responsible for closing the underlying gvisor
// stack + channel endpoints.
func freeSharedStack(handle int32) *sharedStackState {
	sharedStacksMu.Lock()
	defer sharedStacksMu.Unlock()
	s, ok := sharedStacks[handle]
	if !ok {
		return nil
	}
	delete(sharedStacks, handle)
	return s
}

// newSharedStack builds a fresh gvisor stack with v4+v6 + TCP /
// UDP / ICMP transports + forwarding enabled. The stack starts
// with no NICs; callers attach them via [attachNic].
//
// `mtu` is the link-layer MTU for every NIC on this stack. The
// caller has already decided the joiner-N floor (the smallest
// per-joiner MTU) and passes that through.
func newSharedStack(mtu uint32) (*sharedStackState, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol, ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol, udp.NewProtocol,
			icmp.NewProtocol4, icmp.NewProtocol6,
		},
		// HandleLocal=false matches the P1 spike (`joiner_n_router_spike_test.go`):
		// the joiner-N model treats every NIC as a transit interface, not
		// a host endpoint. Locally-destined packets must come out a
		// channel endpoint so our pumps see them, not get dispatched
		// into a transport endpoint we never registered.
		HandleLocal: false,
	})
	// Forwarding on both families — same as P1.
	if err := s.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true); err != nil {
		s.Destroy()
		return nil, fmt.Errorf("set v4 forwarding: %s", err)
	}
	if err := s.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true); err != nil {
		s.Destroy()
		return nil, fmt.Errorf("set v6 forwarding: %s", err)
	}
	ss := &sharedStackState{
		stack:     s,
		endpoints: map[tcpip.NICID]*channel.Endpoint{},
		mtu:       mtu,
	}
	// Seed nextNicID at firstJoinerNicID; NIC `reservedKernelTunNicID`
	// is allocated separately by [attachKernelTunNic] in.
	ss.nextNicID.Store(int32(firstJoinerNicID))
	return ss, nil
}

// closeSharedStack tears down the gvisor stack and every
// associated channel endpoint. If a kernel-TUN pump was attached,
// it's stopped first (which closes the fd and waits for both pump
// goroutines to drain). Idempotent — closing twice is harmless.
func (ss *sharedStackState) close() {
	ss.mu.Lock()
	pumpHandle := ss.pumpHandle
	ss.pumpHandle = nil
	endpoints := ss.endpoints
	ss.endpoints = nil
	ss.mu.Unlock()
	// Stop the pump BEFORE tearing down endpoints / the stack —
	// the pump's reader/writer goroutines reference NIC 1's
	// channel endpoint, and closing that endpoint underneath
	// them is what causes the race we're avoiding here.
	if pumpHandle != nil {
		_ = pumpHandle.Stop()
	}
	for _, ep := range endpoints {
		ep.Close()
	}
	if ss.stack != nil {
		ss.stack.Destroy()
	}
}

// nicMarker returns a synthetic /32 link-local IPv4 marker
// address for NIC [id]. Per the P1 finding, gvisor's strong-host
// model requires *some* local address on each potential outgoing
// NIC before its `FindRoute()` will select that NIC for forwarded
// traffic. Using a deterministic /32 in 169.254.0.0/24 means:
//
//   - Doesn't collide with any joiner's real AllowedIPs (which
//     are app-controlled and never link-local).
//   - Compact: NIC IDs 1..254 each get a unique marker.
//   - Doesn't expose anything externally — link-local is not
//     routed across the WG transport.
//
// The marker stays per-NIC and is never advertised to wireguard-go
// or apps; it exists exclusively to satisfy gvisor's routing model.
func nicMarker(id tcpip.NICID) netip.Addr {
	// Cap at 254 — NIC IDs above that would wrap into the
	// 169.254.0.255 broadcast or roll over into 169.254.1.x. The
	// caller (joiner-N production code) should never need more
	// than a few dozen NICs; we error out before that.
	if id > 254 {
		return netip.AddrFrom4([4]byte{169, 254, 1, byte(id - 254)})
	}
	return netip.AddrFrom4([4]byte{169, 254, 0, byte(id)})
}

// nicMarkerV6 mirrors [nicMarker] for IPv6.  gvisor's strong-host
// model applies per-family — without a v6 local address on every
// potential outgoing NIC, `FindRoute` rejects forwarded v6 packets
// the same way it does v4 (P1 finding, generalized).  Production
// joiners with v6 AllowedIPs would otherwise see silent drops on
// the inbound (joiner → app) path.
//
// Address scheme: `fe80::wgrtc:<id>` in the link-local ULA range,
// guaranteed not to collide with any global v6 prefix a joiner
// could legitimately advertise.
func nicMarkerV6(id tcpip.NICID) netip.Addr {
	var b [16]byte
	b[0] = 0xfe
	b[1] = 0x80
	// "wgrtc" → 0x77 0x67 0x72 0x74 0x63 at bytes [8..12], NIC ID
	// big-endian at [12..16].  Keeps every NIC's marker unique +
	// recognisable in a packet capture.
	b[8] = 'w'
	b[9] = 'g'
	b[10] = 'r'
	b[11] = 't'
	b[12] = 'c'
	b[13] = 0
	b[14] = byte(int32(id) >> 8)
	b[15] = byte(int32(id))
	return netip.AddrFrom16(b)
}

// bindStrongHostMarkers binds [nicID]'s synthetic v4+v6 markers
// via gvisor's AddProtocolAddress.  Called by both [attachNic] and
// [attachKernelTunNic] so every NIC gets both families.  Returns
// an error mirroring the gvisor stack error verbatim; the caller
// is responsible for the rollback (RemoveNIC + ep.Close).
func bindStrongHostMarkers(s *stack.Stack, nicID tcpip.NICID) error {
	v4 := nicMarker(nicID)
	v4Pa := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(
			v4.AsSlice()).WithPrefix(),
	}
	if err := s.AddProtocolAddress(nicID, v4Pa, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("AddProtocolAddress(v4 marker on NIC %d): %s", nicID, err)
	}
	v6 := nicMarkerV6(nicID)
	v6Pa := tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(
			v6.AsSlice()).WithPrefix(),
	}
	if err := s.AddProtocolAddress(nicID, v6Pa, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("AddProtocolAddress(v6 marker on NIC %d): %s", nicID, err)
	}
	return nil
}

// attachNic creates a fresh channel endpoint, registers it as a
// new NIC on the gvisor stack, binds the NIC's synthetic marker
// address, and returns the (nicID, endpoint) pair so the caller
// can wire it to a wireguard-go device.
//
// Mutates [endpoints] under [mu]. The returned endpoint is owned
// by the shared stack — its lifecycle is bound to [close].
func (ss *sharedStackState) attachNic() (tcpip.NICID, *channel.Endpoint, error) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.endpoints == nil {
		return 0, nil, fmt.Errorf("shared stack is closed")
	}
	nicID := tcpip.NICID(ss.nextNicID.Add(1) - 1)
	ep := channel.New(1024, ss.mtu, "")
	if err := ss.stack.CreateNIC(nicID, ep); err != nil {
		ep.Close()
		return 0, nil, fmt.Errorf("CreateNIC(%d): %s", nicID, err)
	}
	// Bind v4 + v6 strong-host markers so gvisor's `FindRoute`
	// will pick this NIC for forwarded traffic of either family.
	// (P1 lesson + dual-stack-correctness review.)
	if err := bindStrongHostMarkers(ss.stack, nicID); err != nil {
		ss.stack.RemoveNIC(nicID)
		ep.Close()
		return 0, nil, err
	}
	ss.endpoints[nicID] = ep
	return nicID, ep, nil
}

// attachKernelTunNic allocates the reserved NIC ID (1) for the
// kernel-TUN side of the shared stack. Production callers wire
// the resulting channel endpoint to a pair of read/write pump
// goroutines that move bytes between the kernel TUN fd and gvisor
// — that wiring is `D4.J2`. This file is just the address /
// route plumbing.
//
// Returns an error if the kernel-TUN NIC is already attached;
// only one is ever expected per shared stack.
func (ss *sharedStackState) attachKernelTunNic() (tcpip.NICID, *channel.Endpoint, error) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.endpoints == nil {
		return 0, nil, fmt.Errorf("shared stack is closed")
	}
	if _, exists := ss.endpoints[reservedKernelTunNicID]; exists {
		return 0, nil, fmt.Errorf("kernel-TUN NIC %d already attached", reservedKernelTunNicID)
	}
	ep := channel.New(1024, ss.mtu, "")
	if err := ss.stack.CreateNIC(reservedKernelTunNicID, ep); err != nil {
		ep.Close()
		return 0, nil, fmt.Errorf("CreateNIC(%d): %s", reservedKernelTunNicID, err)
	}
	// Bind v4 + v6 strong-host markers — same rationale as
	// [attachNic].
	if err := bindStrongHostMarkers(ss.stack, reservedKernelTunNicID); err != nil {
		ss.stack.RemoveNIC(reservedKernelTunNicID)
		ep.Close()
		return 0, nil, err
	}
	ss.endpoints[reservedKernelTunNicID] = ep
	return reservedKernelTunNicID, ep, nil
}

// detachNic removes the NIC from the gvisor stack, drops the
// channel endpoint, and forgets the mapping. Any routes pointing
// at this NIC become dead-letter — gvisor's `FindRoute` skips
// them gracefully ("not enabled"), so no extra cleanup needed.
// Idempotent: detaching a NIC twice is a no-op.
func (ss *sharedStackState) detachNic(nicID tcpip.NICID) error {
	ss.mu.Lock()
	ep, ok := ss.endpoints[nicID]
	if !ok {
		ss.mu.Unlock()
		return nil
	}
	delete(ss.endpoints, nicID)
	ss.mu.Unlock()
	if err := ss.stack.RemoveNIC(nicID); err != nil {
		return fmt.Errorf("RemoveNIC(%d): %s", nicID, err)
	}
	ep.Close()
	return nil
}

// addRoute appends a route to the global route table:
// "send packets whose destination falls in [prefix] out via [nicID]".
// Returns an error if the prefix doesn't parse or the NIC ID
// isn't registered. Caller may add overlapping routes; gvisor
// picks the longest-prefix match per the P1 spike.
//
// IPv4 and IPv6 prefixes are both accepted; the family is
// inferred from the address length.
func (ss *sharedStackState) addRoute(prefix netip.Prefix, nicID tcpip.NICID) error {
	ss.mu.Lock()
	if _, ok := ss.endpoints[nicID]; !ok {
		ss.mu.Unlock()
		return fmt.Errorf("addRoute: NIC %d not registered on this stack", nicID)
	}
	ss.mu.Unlock()
	addrSlice := prefix.Masked().Addr().AsSlice()
	mask := make([]byte, len(addrSlice))
	bits := prefix.Bits()
	full := bits / 8
	rem := bits % 8
	for i := 0; i < full; i++ {
		mask[i] = 0xff
	}
	if rem > 0 && full < len(mask) {
		mask[full] = byte(0xff << uint(8-rem))
	}
	subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice(addrSlice), tcpip.MaskFromBytes(mask))
	if err != nil {
		return fmt.Errorf("NewSubnet(%v): %s", prefix, err)
	}
	ss.stack.AddRoute(tcpip.Route{Destination: subnet, NIC: nicID})
	return nil
}

// addJoinerRoutes wires the routing for one joiner whose:
//   - `peerAllowed` is the list of CIDRs the joiner advertises as
//     reachable through its WG tunnel (forward apps→joiner).
//   - `interfaceAddrs` is the list of /32 (or /128) source IPs the
//     joiner's apps will use (forward joiner→apps; the kernel TUN
//     NIC is where those packets get sent for delivery).
//
// Both lists may be empty (a no-op for that direction). Returns
// an error if any prefix is malformed.
func (ss *sharedStackState) addJoinerRoutes(
	nicID tcpip.NICID,
	peerAllowed []netip.Prefix,
	interfaceAddrs []netip.Prefix,
) error {
	for _, p := range peerAllowed {
		if err := ss.addRoute(p, nicID); err != nil {
			return fmt.Errorf("peer-allowed route %v: %w", p, err)
		}
	}
	// interfaceAddrs use the kernel-TUN NIC, which D4.J2 will
	// register. If the caller adds these BEFORE the kernel-TUN
	// NIC exists, addRoute returns an error. That's by design:
	// joiner-N production code adds joiners only after binding
	// the kernel TUN.
	for _, p := range interfaceAddrs {
		if err := ss.addRoute(p, reservedKernelTunNicID); err != nil {
			return fmt.Errorf("interface-addr route %v: %w", p, err)
		}
	}
	return nil
}

// _ usage to silence unused-import warnings on builds where this
// file's exported functions might not all be referenced. The same
// pattern as `api.go`'s tail.
var _ header.ARPHardwareType
