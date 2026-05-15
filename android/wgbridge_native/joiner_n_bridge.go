// Joiner-N's per-bridge wiring (D4.J2 part 2): a `tun.Device`
// adapter that lives between wireguard-go and a `channel.Endpoint`
// on the shared stack, plus `openJoinerBridge` that constructs a
// full wireguard-go device on this adapter and programs routes.
//
// **Topology recap** (`docs/cascade-n-design.md` §Primary):
//
//	     kernel TUN fd
//	          │   (pumps from `joiner_n_pump.go`)
//	          ▼
//	    ┌─ shared gvisor stack ──┐
//	    │  NIC 1  ← kernel-TUN   │
//	    │  NIC 2  ← joiner-A     │ ←┐
//	    │  NIC 3  ← joiner-B     │ ←┐   ← per-joiner channel endpoints
//	    │  ...                   │ ←┐
//	    └────────────────────────┘
//	                                │
//	                                │   per-joiner tun.Device adapter
//	                                ▼
//	                          wg-go #i  (encrypt / decrypt)
//	                                │
//	                                ▼
//	                          protect()'d UDP socket
//	                                │
//	                                ▼
//	                              wire
//
// The adapter (`sharedNicLink`) is wireguard-go's `tun.Device`
// from the bridge's perspective:
//
//   - `Read()`  ← gvisor wants to send a packet OUT this NIC
//     (i.e. it routed an app-side packet here for the joiner to
//     encrypt + transmit).
//   - `Write()` ← wireguard-go received + decrypted a packet on
//     the wire and is delivering it INTO gvisor.
//
// Mirrors `golang.zx2c4.com/wireguard/tun/netstack.netTun` from
// the wg-go source tree, but wraps a SHARED stack's endpoint
// instead of creating a private one.

package main

import (
	"fmt"
	"net/netip"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// sharedNicLink implements wireguard-go's `tun.Device` interface
// against one NIC of a shared gvisor stack. Read drains the
// endpoint's outbound queue (packets gvisor decided this joiner
// should transmit); Write injects into the inbound queue (wg-go
// is delivering a decrypted packet that gvisor should forward to
// the kernel-TUN side).
//
// Lifecycle: owned by a `bridgeState`; closed via wireguard-go's
// `device.Close()` → `tun.Device.Close()`. Closing detaches the
// NIC from the shared stack so any routes pointing here become
// dead-letter.
type sharedNicLink struct {
	ep    *channel.Endpoint
	mtu   int
	ss    *sharedStackState
	nicID tcpip.NICID

	events         chan tun.Event
	incomingPacket chan *buffer.View
	notifyHandle   *channel.NotificationHandle

	closeMu sync.Mutex
	closed  bool
}

// newSharedNicLink wires the adapter, registers a notify callback
// on the endpoint, and signals tun.EventUp so wireguard-go sees
// the link as ready. The caller hands the returned adapter to
// `device.NewDevice`.
func newSharedNicLink(
	ss *sharedStackState,
	nicID tcpip.NICID,
	ep *channel.Endpoint,
	mtu int,
) *sharedNicLink {
	l := &sharedNicLink{
		ep:             ep,
		mtu:            mtu,
		ss:             ss,
		nicID:          nicID,
		events:         make(chan tun.Event, 10),
		incomingPacket: make(chan *buffer.View, 64),
	}
	l.notifyHandle = ep.AddNotify(l)
	l.events <- tun.EventUp
	return l
}

// WriteNotify is gvisor's callback — fires when a packet lands
// on this endpoint's outbound queue (i.e. gvisor decided to send
// it out this NIC). Pulls the packet, posts to incomingPacket
// so wireguard-go's Read goroutine picks it up.
//
// Race-safe against [Close]: the `closeMu` guard ensures we
// never send on a closed channel. If WriteNotify fires AFTER
// Close held the lock, we observe `l.closed` and bail.
func (l *sharedNicLink) WriteNotify() {
	l.closeMu.Lock()
	if l.closed {
		l.closeMu.Unlock()
		return
	}
	pkt := l.ep.Read()
	if pkt == nil {
		l.closeMu.Unlock()
		return
	}
	view := pkt.ToView()
	pkt.DecRef()
	select {
	case l.incomingPacket <- view:
	default:
		// Bounded back-pressure: drop on overflow, matching the
		// kernel TUN's xmit-queue behaviour. wireguard-go is
		// behind on this joiner; UDP loses, TCP retransmits.
		view.Release()
	}
	l.closeMu.Unlock()
}

// Read pulls the next outbound-from-gvisor packet (which wg-go
// will then encrypt + send on the wire).
func (l *sharedNicLink) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	view, ok := <-l.incomingPacket
	if !ok {
		return 0, os.ErrClosed
	}
	n, err := view.Read(bufs[0][offset:])
	if err != nil {
		view.Release()
		return 0, err
	}
	view.Release()
	sizes[0] = n
	return 1, nil
}

// Write hands a decrypted packet from wireguard-go into gvisor
// as if it arrived from the NIC's link layer. IPv4 vs IPv6
// distinguished by byte 0's upper nibble; non-IP frames are
// dropped (TUN-mode wg-go shouldn't produce them).
func (l *sharedNicLink) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		packet := buf[offset:]
		if len(packet) == 0 {
			continue
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(packet),
		})
		switch packet[0] >> 4 {
		case 4:
			l.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			l.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			pkb.DecRef()
		}
	}
	return len(bufs), nil
}

// Close detaches the NIC from the shared stack, drops the
// notify callback, and closes the channels. Idempotent.
func (l *sharedNicLink) Close() error {
	l.closeMu.Lock()
	defer l.closeMu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	l.ep.RemoveNotify(l.notifyHandle)
	close(l.events)
	// Drain anything in flight so views get released.
	go func() {
		for v := range l.incomingPacket {
			v.Release()
		}
	}()
	close(l.incomingPacket)
	// Detach this NIC from the shared stack — its routes become
	// dead-letter, which gvisor's FindRoute handles by skipping
	// "not enabled" entries.
	_ = l.ss.detachNic(l.nicID)
	return nil
}

// MTU returns the bridge's MTU as advertised to wireguard-go.
func (l *sharedNicLink) MTU() (int, error) { return l.mtu, nil }

// Name is the link's user-visible name. Not used by wireguard-go's
// routing — purely cosmetic. Match the pattern of netstack's
// "go" string.
func (l *sharedNicLink) Name() (string, error) { return "joiner-n", nil }

// File returns nil — there's no underlying *os.File for a
// channel-endpoint-backed link.
func (l *sharedNicLink) File() *os.File { return nil }

// Events feeds wireguard-go's link-state-change machinery.
func (l *sharedNicLink) Events() <-chan tun.Event { return l.events }

// BatchSize — one packet per Read.  wireguard-go uses this for
// its Read buffer-pool sizing; 1 matches the single-slot
// `incomingPacket` consumer model.
func (l *sharedNicLink) BatchSize() int { return 1 }

// openJoinerBridge attaches a new NIC to [ss], wires a
// wireguard-go device to it, programs the per-joiner routes,
// and registers the resulting bridge in the existing `bridges`
// handle map. Returns the bridge handle the caller passes to
// `wgbridgeConfigureUAPI` / `wgbridgeClose` / etc.
//
//   - `peerAllowed`     → routes forwarding apps → this joiner.
//   - `interfaceAddrs`  → routes the joiner's app-side IPs back
//     to the kernel-TUN NIC (the inbound direction).
//
// On any error along the way, every partial step is unwound:
// device closed, link closed, NIC detached. No leaked goroutines
// or stale routes.
func openJoinerBridge(
	ss *sharedStackState,
	peerAllowed, interfaceAddrs []netip.Prefix,
	mtu int,
) (int32, tcpip.NICID, error) {
	if ss == nil {
		return 0, 0, fmt.Errorf("openJoinerBridge: nil shared stack")
	}
	nicID, ep, err := ss.attachNic()
	if err != nil {
		return 0, 0, fmt.Errorf("attachNic: %w", err)
	}
	link := newSharedNicLink(ss, nicID, ep, mtu)
	logger := makeWgLogger()
	dev := device.NewDevice(link, conn.NewDefaultBind(), logger)
	if err := dev.Up(); err != nil {
		_ = link.Close() // also detaches the NIC
		return 0, 0, fmt.Errorf("device.Up: %w", err)
	}
	if err := ss.addJoinerRoutes(nicID, peerAllowed, interfaceAddrs); err != nil {
		dev.Close() // dev.Close calls link.Close which detaches the NIC.
		return 0, 0, fmt.Errorf("addJoinerRoutes: %w", err)
	}
	bs := &bridgeState{
		dev:    dev,
		tunDev: link,
		logger: logger,
	}
	return allocateHandle(bs), nicID, nil
}
