// CASCADE-2 ferry registry — the process-singleton lifecycle
// owner that decides when to create/destroy ferries based on
// host-mode + joiner-N backend events.
//
// Per docs/cascade-2-plan.md §5 + §8: tracks the currently-active
// joiner-N shared stack and the set of active host bridges.  A
// ferry exists for each (host-bridge, joiner-stack) pair when
// both are present.  When the joiner stack unregisters (the
// rebuild-gap case), cascade routes on each host stack are
// swapped to a per-host-stack synthetic "drop-NIC" (cap=0
// channel.Endpoint) so packets get dropped instead of leaking
// through the host_forwarder's catchall.
//
// All exported methods are safe for concurrent use.

package main

import (
	"net/netip"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	gvstack "gvisor.dev/gvisor/pkg/tcpip/stack"
)

// cascadeFerryRegistrySingleton is the process-singleton instance.
// Production code goes through [getCascadeFerryRegistry] /
// [setCascadeFerryRegistryForTest] for the swap-on-test indirection.
// Until Phase 7 wires the Kotlin side, the registry exists but no
// backend pokes it — host_forwarder's HasCascadePrefix check
// returns false because joinerAllowedIPs is empty.
var cascadeFerryRegistrySingleton atomic.Pointer[CascadeFerryRegistry]

func init() {
	cascadeFerryRegistrySingleton.Store(newCascadeFerryRegistry())
}

// getCascadeFerryRegistry returns the active registry singleton.
func getCascadeFerryRegistry() *CascadeFerryRegistry {
	return cascadeFerryRegistrySingleton.Load()
}

// setCascadeFerryRegistryForTest replaces the singleton with [r]
// and returns a restore function the test can defer.  Not safe
// for use in production — only tests should call this.
func setCascadeFerryRegistryForTest(r *CascadeFerryRegistry) func() {
	old := cascadeFerryRegistrySingleton.Load()
	cascadeFerryRegistrySingleton.Store(r)
	return func() { cascadeFerryRegistrySingleton.Store(old) }
}

// tcpipAddressToNetip converts a gvisor tcpip.Address to a
// netip.Addr.  Returns (zero, false) for empty / unsupported
// length.
func tcpipAddressToNetip(a tcpip.Address) (netip.Addr, bool) {
	switch a.Len() {
	case 4:
		b := a.As4()
		return netip.AddrFrom4(b), true
	case 16:
		b := a.As16()
		return netip.AddrFrom16(b), true
	}
	return netip.Addr{}, false
}

// CascadeFerryRegistry is the process-singleton owner.
type CascadeFerryRegistry struct {
	mu sync.Mutex

	// joinerStack is the currently-active joiner-N shared stack,
	// or nil between Register and Unregister calls.
	joinerStack *gvstack.Stack
	// joinerAllowedIPs is the union of every active joiner peer's
	// AllowedIPs.  Routes on each host stack point cascade prefixes
	// at the ferry NIC (or drop-NIC during the gap).
	joinerAllowedIPs []netip.Prefix

	// joinerOwnV4 / joinerOwnV6 — the joiner-N's own assigned
	// addresses (the wg-quick `[Interface] Address` line of the
	// first/only joiner).  Used by the CASCADE-2 NAT to rewrite
	// cascade traffic's inner source so the upstream WG server
	// accepts it without requiring server-side AllowedIPs
	// widening.  Zero-valued = NAT disabled for that family.
	//
	// Single-joiner MVP: each ferry's NatTable is configured with
	// these on creation.  Multi-joiner support (= per-joiner NAT
	// state + PAT) is a follow-up.
	joinerOwnV4 netip.Addr
	joinerOwnV6 netip.Addr

	// hostStacks holds the active host-mode bridges, keyed by
	// bridge handle.
	hostStacks map[int32]*hostStackEntry

	// ferries: one per (host bridge handle, joiner stack) — but
	// since there's at most one joiner stack at a time, we just
	// key by host bridge handle.
	ferries map[int32]*CascadeFerry
}

type hostStackEntry struct {
	stack        *gvstack.Stack
	peerSubnets  []netip.Prefix
	// dropNicID is the synthetic drop-NIC on this host stack used
	// during the joiner-N rebuild gap.  Created on first ferry
	// registration on this host stack, never destroyed until the
	// host bridge itself is unregistered (at which point the host
	// stack dies with it).
	dropNicID tcpip.NICID
	dropEp    *channel.Endpoint
}

func newCascadeFerryRegistry() *CascadeFerryRegistry {
	return &CascadeFerryRegistry{
		hostStacks: make(map[int32]*hostStackEntry),
		ferries:    make(map[int32]*CascadeFerry),
	}
}

// RegisterJoinerStack records the joiner-N shared stack + the
// union of AllowedIPs of its active joiners.  If any host bridges
// are already registered, creates a ferry for each and installs
// routes.
func (r *CascadeFerryRegistry) RegisterJoinerStack(s *gvstack.Stack, allowedIPs []netip.Prefix) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.joinerStack = s
	r.joinerAllowedIPs = dedupePrefixes(allowedIPs)
	// Create ferries for each existing host bridge.
	for handle, entry := range r.hostStacks {
		r.createFerryLocked(handle, entry)
	}
}

// UnregisterJoinerStack handles the joiner-N teardown.  Stops all
// ferries (cancelling their drain goroutines and waiting for them
// to exit), swaps each host stack's cascade routes from the ferry
// NIC to the per-host-stack drop-NIC.  Per docs §8: this MUST
// complete before the joiner stack is torn down so the drain
// goroutines don't race a dying stack.
func (r *CascadeFerryRegistry) UnregisterJoinerStack() {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Swap routes to drop-NIC first, then stop ferries.
	for handle, ferry := range r.ferries {
		entry := r.hostStacks[handle]
		if entry == nil {
			continue
		}
		r.swapCascadeRoutesToDropNicLocked(ferry, entry)
		ferry.Stop()
		delete(r.ferries, handle)
	}
	r.joinerStack = nil
	r.joinerAllowedIPs = nil
}

// RegisterHostBridge records a host-mode bridge.  If the joiner
// stack is present, creates a ferry and installs routes.
func (r *CascadeFerryRegistry) RegisterHostBridge(handle int32, s *gvstack.Stack, peerSubnets []netip.Prefix) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := &hostStackEntry{
		stack:       s,
		peerSubnets: dedupePrefixes(peerSubnets),
	}
	// Create the per-host-stack drop-NIC.  cap=0 channel.Endpoint
	// silently drops all packets sent to it (verified against
	// gvisor's channel.queue.Write).
	dropEp := channel.New(0, 1500 /* mtu */, "")
	dropNicID := pickFreeNicID(s)
	if err := s.CreateNIC(dropNicID, dropEp); err != nil {
		// Drop-NIC creation failed; we still register the host
		// bridge, but cascade won't survive a rebuild gap.  Log
		// (TODO: wire to hostFwdLog once that's available here)
		// and continue.
		entry.dropNicID = 0
		entry.dropEp = nil
	} else {
		entry.dropNicID = dropNicID
		entry.dropEp = dropEp
	}
	r.hostStacks[handle] = entry
	if r.joinerStack != nil {
		r.createFerryLocked(handle, entry)
	}
}

// UnregisterHostBridge removes a host bridge.  If a ferry exists
// for it, stops it.  Cascade routes on the host stack are removed
// (since the host stack itself is about to go away too).
func (r *CascadeFerryRegistry) UnregisterHostBridge(handle int32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ferry, ok := r.ferries[handle]; ok {
		ferry.Stop()
		delete(r.ferries, handle)
	}
	entry, ok := r.hostStacks[handle]
	if !ok {
		return
	}
	// Remove any cascade routes still on the host stack (e.g.
	// drop-NIC routes from a UnregisterJoinerStack that hasn't
	// been paired with a re-register yet).
	for _, prefix := range r.joinerAllowedIPs {
		subnet, err := prefixToSubnet(prefix)
		if err != nil {
			continue
		}
		entry.stack.RemoveRoutes(func(rt tcpip.Route) bool {
			return rt.Destination.Equal(subnet) &&
				(rt.NIC == entry.dropNicID)
		})
	}
	if entry.dropNicID != 0 {
		entry.stack.RemoveNIC(entry.dropNicID)
		entry.dropEp.Close()
	}
	delete(r.hostStacks, handle)
}

// OnJoinerInterfaceAddrsChanged updates the joiner's own assigned
// WG-side addresses (CASCADE-2 NAT source).  Propagates to every
// active ferry so cascade traffic gets SNAT'd to the new values.
// Zero-valued addresses disable NAT for that family.
//
// Idempotent: same values → no observable effect.
func (r *CascadeFerryRegistry) OnJoinerInterfaceAddrsChanged(v4, v6 netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v4.IsValid() && !v4.Is4() {
		v4 = netip.Addr{}
	}
	if v6.IsValid() && !v6.Is6() {
		v6 = netip.Addr{}
	}
	r.joinerOwnV4 = v4
	r.joinerOwnV6 = v6
	for _, ferry := range r.ferries {
		ferry.SetJoinerInterfaceAddrs(v4, v6)
	}
}

// OnJoinerAllowedIPsChanged updates the cascade route set when
// joiner-N's union of AllowedIPs changes (e.g. a joiner is added
// or removed without a full stack rebuild).  Adds routes for
// new prefixes, removes routes for prefixes that went away.
func (r *CascadeFerryRegistry) OnJoinerAllowedIPsChanged(allowedIPs []netip.Prefix) {
	r.mu.Lock()
	defer r.mu.Unlock()
	newSet := dedupePrefixes(allowedIPs)
	oldSet := r.joinerAllowedIPs

	// Compute deltas.
	added, removed := prefixSetDiff(oldSet, newSet)

	for handle, ferry := range r.ferries {
		entry := r.hostStacks[handle]
		if entry == nil {
			continue
		}
		for _, p := range removed {
			_ = ferry.RemoveHostRoute(p)
		}
		for _, p := range added {
			_ = ferry.AddHostRoute(p)
		}
	}
	r.joinerAllowedIPs = newSet
}

// HasCascadePrefix returns true if [addr] falls under any active
// cascade prefix.  Used by host_forwarder's redirectViaTempAddress
// to skip registering temp-locals that would shadow a cascade
// route.
func (r *CascadeFerryRegistry) HasCascadePrefix(addr netip.Addr) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.joinerAllowedIPs {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// activeFerryCount is a test helper.
func (r *CascadeFerryRegistry) activeFerryCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.ferries)
}

// createFerryLocked builds a ferry between r.joinerStack and the
// given host bridge, installs cascade routes in both directions.
// Caller MUST hold r.mu.
func (r *CascadeFerryRegistry) createFerryLocked(handle int32, entry *hostStackEntry) {
	// 1500 MTU is the typical max for tunneled traffic; the ferry
	// itself doesn't fragment.  Could be derived from
	// min(host, joiner) but both stacks today use 1500.
	const mtu uint32 = 1500
	ferry, err := newCascadeFerry(entry.stack, r.joinerStack, mtu)
	if err != nil {
		return
	}
	// Seed the NAT with the currently-cached joiner-own addresses.
	// Zero values = NAT disabled for that family (pure passthrough).
	ferry.SetJoinerInterfaceAddrs(r.joinerOwnV4, r.joinerOwnV6)
	// Install host-side routes: every joiner AllowedIP → ferry's
	// host NIC.  Before adding, remove any drop-NIC route for
	// the same prefix (left over from a prior UnregisterJoinerStack).
	for _, prefix := range r.joinerAllowedIPs {
		if entry.dropNicID != 0 {
			subnet, err := prefixToSubnet(prefix)
			if err == nil {
				entry.stack.RemoveRoutes(func(rt tcpip.Route) bool {
					return rt.Destination.Equal(subnet) && rt.NIC == entry.dropNicID
				})
			}
		}
		_ = ferry.AddHostRoute(prefix)
	}
	// Install joiner-side routes: this host's peerSubnets → ferry's
	// joiner NIC.
	for _, prefix := range entry.peerSubnets {
		_ = ferry.AddJoinerRoute(prefix)
	}
	r.ferries[handle] = ferry
}

// swapCascadeRoutesToDropNicLocked replaces host-stack cascade
// routes (currently pointing at the ferry NIC) with routes
// pointing at the host-stack's drop-NIC.  Caller MUST hold r.mu.
//
// After this call, packets matching cascade prefixes on the host
// stack go to a cap=0 channel.Endpoint where channel.queue.Write
// drops them silently.  The host_forwarder's catchall never sees
// them.
func (r *CascadeFerryRegistry) swapCascadeRoutesToDropNicLocked(ferry *CascadeFerry, entry *hostStackEntry) {
	if entry.dropNicID == 0 {
		// No drop-NIC available; cascade routes will be removed
		// by ferry.Stop() and packets will fall through to the
		// host_forwarder's catchall (leak window).  Best-effort.
		return
	}
	// Capture the prefixes from the ferry's hostRoutes before we
	// stop it — ferry.Stop tears down its hostRoutes map.
	ferry.mu.Lock()
	prefixes := make([]netip.Prefix, 0, len(ferry.hostRoutes))
	for p := range ferry.hostRoutes {
		prefixes = append(prefixes, p)
	}
	ferry.mu.Unlock()
	// For each cascade prefix: drop ferry-NIC route, add drop-NIC
	// route in its place.
	for _, prefix := range prefixes {
		subnet, err := prefixToSubnet(prefix)
		if err != nil {
			continue
		}
		entry.stack.RemoveRoutes(func(rt tcpip.Route) bool {
			return rt.Destination.Equal(subnet) && rt.NIC == ferry.hostNicID
		})
		entry.stack.AddRoute(tcpip.Route{
			Destination: subnet,
			NIC:         entry.dropNicID,
		})
	}
	// Clear the ferry's own bookkeeping so its Stop() doesn't
	// try to remove the routes we just took over.
	ferry.mu.Lock()
	ferry.hostRoutes = make(map[netip.Prefix]struct{})
	ferry.mu.Unlock()
}

// dedupePrefixes returns a copy of [in] with duplicates removed,
// preserving first-occurrence order.
func dedupePrefixes(in []netip.Prefix) []netip.Prefix {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[netip.Prefix]struct{}, len(in))
	out := make([]netip.Prefix, 0, len(in))
	for _, p := range in {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

// prefixSetDiff returns (added, removed) such that
// newSet = (oldSet \ removed) ∪ added.
func prefixSetDiff(oldSet, newSet []netip.Prefix) (added, removed []netip.Prefix) {
	oldMap := make(map[netip.Prefix]struct{}, len(oldSet))
	for _, p := range oldSet {
		oldMap[p] = struct{}{}
	}
	newMap := make(map[netip.Prefix]struct{}, len(newSet))
	for _, p := range newSet {
		newMap[p] = struct{}{}
	}
	for _, p := range newSet {
		if _, ok := oldMap[p]; !ok {
			added = append(added, p)
		}
	}
	for _, p := range oldSet {
		if _, ok := newMap[p]; !ok {
			removed = append(removed, p)
		}
	}
	return added, removed
}
