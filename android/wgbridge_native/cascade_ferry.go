// CASCADE-2 cross-stack packet ferry.
//
// Plumbs IP packets between a host-mode gvisor stack
// (HandleLocal=true, owned by netstack.CreateNetTUN today) and the
// joiner-N shared gvisor stack (HandleLocal=false).  Each direction
// has its own drain-loop goroutine that reads packets off the
// source stack's ferry NIC channel.Endpoint and delivers them
// inbound on the destination stack's ferry NIC via
// `InjectInbound`.
//
// Design rationale + alternatives considered: see
// docs/cascade-2-plan.md (Option B, after rejecting unified stack
// in v3 review on HandleLocal-collision grounds).
//
// **Why InjectInbound, not WritePackets**: a stack's
// channel.Endpoint.WritePackets queues for `Read` — i.e. it's the
// outbound-from-the-stack direction.  We want the destination
// stack to *receive* the packet as if from the wire, which is
// `InjectInbound`.  Same primitive joiner_n_pump.go uses on
// line 91 for kernel-TUN reads.
//
// **Why strong-host markers only on the joiner side**: the joiner
// stack runs HandleLocal=false and requires every NIC to have at
// least one address for gvisor's FindRoute to consider it a
// candidate egress.  The host stack runs HandleLocal=true and
// doesn't need markers; binding them there would just clutter
// the address table.

package main

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	gvstack "gvisor.dev/gvisor/pkg/tcpip/stack"
)

// CascadeFerry forwards IP packets between two gvisor stacks via
// a paired channel.Endpoint.
//
// Lifecycle: caller invokes [newCascadeFerry], then optionally
// installs cascade routes via [AddHostRoute] / [AddJoinerRoute],
// then [Stop] to tear down.  The host-side NIC stays alive
// across the joiner stack's rebuild gap so its cascade routes
// persist (see plan §8); the registry is responsible for
// reaching into the ferry and updating joinerStack/joinerEp on
// rebuild.
type CascadeFerry struct {
	hostStack   *gvstack.Stack
	joinerStack *gvstack.Stack

	hostNicID   tcpip.NICID
	joinerNicID tcpip.NICID
	hostEp      *channel.Endpoint
	joinerEp    *channel.Endpoint

	mtu uint32

	ctx              context.Context
	cancel           context.CancelFunc
	hostToJoinerDone chan struct{}
	joinerToHostDone chan struct{}

	// routes track the prefixes we installed on each stack, for
	// graceful removal in Stop.
	mu             sync.Mutex
	hostRoutes     map[netip.Prefix]struct{}
	joinerRoutes   map[netip.Prefix]struct{}
}

// newCascadeFerry creates a ferry between hostStack and joinerStack
// with MTU [mtu].  Allocates a fresh NIC ID on each stack
// (highest-in-use + 1) and binds strong-host markers only on the
// joiner-side NIC.  Starts the two drain-loop goroutines.
func newCascadeFerry(
	hostStack, joinerStack *gvstack.Stack, mtu uint32,
) (*CascadeFerry, error) {
	if hostStack == nil || joinerStack == nil {
		return nil, fmt.Errorf("newCascadeFerry: nil stack")
	}
	if mtu == 0 {
		return nil, fmt.Errorf("newCascadeFerry: zero MTU")
	}

	hostNicID := pickFreeNicID(hostStack)
	joinerNicID := pickFreeNicID(joinerStack)

	hostEp := channel.New(64, mtu, "")
	joinerEp := channel.New(64, mtu, "")

	// Wire host-side NIC first.  If we fail, no cleanup needed
	// because nothing else touched these endpoints yet.
	if err := hostStack.CreateNIC(hostNicID, hostEp); err != nil {
		return nil, fmt.Errorf("hostStack.CreateNIC(%d): %s", hostNicID, err)
	}
	if err := joinerStack.CreateNIC(joinerNicID, joinerEp); err != nil {
		hostStack.RemoveNIC(hostNicID)
		return nil, fmt.Errorf("joinerStack.CreateNIC(%d): %s", joinerNicID, err)
	}

	// Strong-host markers on BOTH ferry NICs.  Joiner stack runs
	// HandleLocal=false where the rule is strict.  Host stack runs
	// HandleLocal=true, where local-delivery decisions don't
	// require markers — but gvisor's FORWARDING path still consults
	// the egress NIC's addresses for source-address candidate
	// selection.  v6 forwarding in particular drops packets when
	// the egress NIC has no address of the matching family.
	if err := bindStrongHostMarkers(joinerStack, joinerNicID); err != nil {
		hostStack.RemoveNIC(hostNicID)
		joinerStack.RemoveNIC(joinerNicID)
		return nil, fmt.Errorf("bindStrongHostMarkers(joiner): %s", err)
	}
	if err := bindStrongHostMarkers(hostStack, hostNicID); err != nil {
		hostStack.RemoveNIC(hostNicID)
		joinerStack.RemoveNIC(joinerNicID)
		return nil, fmt.Errorf("bindStrongHostMarkers(host): %s", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	f := &CascadeFerry{
		hostStack:        hostStack,
		joinerStack:      joinerStack,
		hostNicID:        hostNicID,
		joinerNicID:      joinerNicID,
		hostEp:           hostEp,
		joinerEp:         joinerEp,
		mtu:              mtu,
		ctx:              ctx,
		cancel:           cancel,
		hostToJoinerDone: make(chan struct{}),
		joinerToHostDone: make(chan struct{}),
		hostRoutes:       make(map[netip.Prefix]struct{}),
		joinerRoutes:     make(map[netip.Prefix]struct{}),
	}

	go f.drainLoop(hostEp, joinerEp, f.hostToJoinerDone)
	go f.drainLoop(joinerEp, hostEp, f.joinerToHostDone)

	return f, nil
}

// drainLoop reads packets off [src] and re-injects them as inbound
// on [dst].  Exits when ctx is cancelled OR src.Close() makes
// ReadContext return nil.
func (f *CascadeFerry) drainLoop(src, dst *channel.Endpoint, done chan struct{}) {
	defer close(done)
	for {
		pkt := src.ReadContext(f.ctx)
		if pkt == nil {
			return
		}
		// Determine network protocol from the IP version nibble.
		view := pkt.ToView()
		raw := view.AsSlice()
		var proto tcpip.NetworkProtocolNumber
		if len(raw) == 0 {
			pkt.DecRef()
			view.Release()
			continue
		}
		switch raw[0] >> 4 {
		case 4:
			proto = header.IPv4ProtocolNumber
		case 6:
			proto = header.IPv6ProtocolNumber
		default:
			// Garbage from the source stack — drop.
			pkt.DecRef()
			view.Release()
			continue
		}
		// Clone into a fresh packet buffer.  InjectInbound takes
		// ownership of its buffer's lifecycle through the stack's
		// reference-counting machinery; we DecRef our copy after
		// the call to release our hold.
		rawCopy := make([]byte, len(raw))
		copy(rawCopy, raw)
		view.Release()
		pkt.DecRef()
		clone := gvstack.NewPacketBuffer(gvstack.PacketBufferOptions{
			Payload: buffer.MakeWithData(rawCopy),
		})
		dst.InjectInbound(proto, clone)
		clone.DecRef()
	}
}

// AddHostRoute adds a route on the host stack: [prefix] →
// f.hostNicID.  Idempotent — duplicate calls return nil without
// adding twice.
func (f *CascadeFerry) AddHostRoute(prefix netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.hostRoutes[prefix]; exists {
		return nil
	}
	subnet, err := prefixToSubnet(prefix)
	if err != nil {
		return err
	}
	f.hostStack.AddRoute(tcpip.Route{Destination: subnet, NIC: f.hostNicID})
	f.hostRoutes[prefix] = struct{}{}
	return nil
}

// AddJoinerRoute adds a route on the joiner stack: [prefix] →
// f.joinerNicID.
func (f *CascadeFerry) AddJoinerRoute(prefix netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.joinerRoutes[prefix]; exists {
		return nil
	}
	subnet, err := prefixToSubnet(prefix)
	if err != nil {
		return err
	}
	f.joinerStack.AddRoute(tcpip.Route{Destination: subnet, NIC: f.joinerNicID})
	f.joinerRoutes[prefix] = struct{}{}
	return nil
}

// RemoveHostRoute removes a previously-added host-side route.
// Returns nil even when the route wasn't present (idempotent).
func (f *CascadeFerry) RemoveHostRoute(prefix netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.hostRoutes[prefix]; !exists {
		return nil
	}
	subnet, err := prefixToSubnet(prefix)
	if err != nil {
		return err
	}
	f.hostStack.RemoveRoutes(func(r tcpip.Route) bool {
		return r.NIC == f.hostNicID && r.Destination.Equal(subnet)
	})
	delete(f.hostRoutes, prefix)
	return nil
}

// RemoveJoinerRoute removes a previously-added joiner-side route.
func (f *CascadeFerry) RemoveJoinerRoute(prefix netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.joinerRoutes[prefix]; !exists {
		return nil
	}
	subnet, err := prefixToSubnet(prefix)
	if err != nil {
		return err
	}
	f.joinerStack.RemoveRoutes(func(r tcpip.Route) bool {
		return r.NIC == f.joinerNicID && r.Destination.Equal(subnet)
	})
	delete(f.joinerRoutes, prefix)
	return nil
}

// Stop cancels both drain-loop goroutines, waits for them to
// exit, removes all installed routes, and detaches both NICs.
// Idempotent.
func (f *CascadeFerry) Stop() {
	f.cancel()
	// Closing the channel.Endpoints unblocks any ReadContext that
	// happens to be waiting between cancel-check and queue-pop.
	f.hostEp.Close()
	f.joinerEp.Close()
	<-f.hostToJoinerDone
	<-f.joinerToHostDone

	f.mu.Lock()
	defer f.mu.Unlock()
	for prefix := range f.hostRoutes {
		if subnet, err := prefixToSubnet(prefix); err == nil {
			f.hostStack.RemoveRoutes(func(r tcpip.Route) bool {
				return r.NIC == f.hostNicID && r.Destination.Equal(subnet)
			})
		}
	}
	for prefix := range f.joinerRoutes {
		if subnet, err := prefixToSubnet(prefix); err == nil {
			f.joinerStack.RemoveRoutes(func(r tcpip.Route) bool {
				return r.NIC == f.joinerNicID && r.Destination.Equal(subnet)
			})
		}
	}
	f.hostRoutes = nil
	f.joinerRoutes = nil
	f.hostStack.RemoveNIC(f.hostNicID)
	f.joinerStack.RemoveNIC(f.joinerNicID)
}

// pickFreeNicID returns the lowest unused NIC ID on [s].  Starts
// at 1; gvisor's NICID 0 is invalid.
func pickFreeNicID(s *gvstack.Stack) tcpip.NICID {
	info := s.NICInfo()
	next := tcpip.NICID(1)
	for {
		if _, taken := info[next]; !taken {
			return next
		}
		next++
	}
}

// prefixToSubnet converts a netip.Prefix to a tcpip.Subnet.
// Same shape as the converter in joiner_n_stack.go's addRoute.
func prefixToSubnet(prefix netip.Prefix) (tcpip.Subnet, error) {
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
	return tcpip.NewSubnet(tcpip.AddrFromSlice(addrSlice),
		tcpip.MaskFromBytes(mask))
}
