//go:build android

// Protect-aware conn.Bind for the joiner path.
//
// **Why this exists.** When wgbridge_native is loaded inside a
// VpnService, the OS routes every outbound packet that matches the
// VPN's AllowedIPs (typically `0.0.0.0/0` for full-tunnel joiners)
// into the tun. wireguard-go's own outbound UDP to the server
// is matched too — every encrypted packet gets pulled back into
// the tun, re-encrypted, sent again, looping at line rate.
//
// The fix Android exposes is `VpnService.protect(int fd)` which
// marks a socket as "send straight to the underlying network,
// don't route through the tun". We have to call protect AFTER
// `socket()` but BEFORE `bind()` — that's exactly the window
// `net.ListenConfig.Control` opens up.
//
// Implementation: a minimal `conn.Bind` that creates a single v4
// + (best-effort) v6 UDP socket per `Open()`, calls into Java
// via cgo to protect each fd before bind, and otherwise behaves
// like a tiny version of wireguard-go's `StdNetBind` (no GSO, no
// batching, no sticky-source PKTINFO — none of which matters for
// the joiner path).
//
// The process-global protector callback is installed by the
// Kotlin side via `WgBridgeNative.installProtector` before
// `wgbridgeNewWithTunFd` runs; this Bind looks it up through the
// `wgbridge_dispatch_protect_fd` C function.

package main

/*
extern int wgbridge_dispatch_protect_fd(int fd);
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"golang.zx2c4.com/wireguard/conn"
)

// protectingBind is a conn.Bind that protects every UDP socket via
// the Kotlin-side VpnService.protect callback before binding.
type protectingBind struct {
	mu sync.Mutex
	closed bool
	v4 *net.UDPConn
	v6 *net.UDPConn
	port uint16
}

func newProtectingBind() *protectingBind { return &protectingBind{} }

// makeListenConfig returns a *net.ListenConfig whose Control
// callback extracts the fd, hands it to Java for protect(), and
// fails the open if Java refuses. Without this, listenConfig.Control
// is the documented hook for between-socket-and-bind work.
func makeListenConfig() *net.ListenConfig {
	return &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var protectErr error
			if err := c.Control(func(fd uintptr) {
				if rc := C.wgbridge_dispatch_protect_fd(C.int(fd)); rc == 0 {
					protectErr = fmt.Errorf(
						"VpnService.protect(fd=%d) refused; tunnel would route-loop", fd)
				}
			}); err != nil {
				return err
			}
			return protectErr
		},
	}
}

func (b *protectingBind) Open(uport uint16) (
	[]conn.ReceiveFunc, uint16, error,
) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.v4 != nil || b.v6 != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	// wireguard-go's BindUpdate calls Close() then Open() on the
	// same Bind instance; without this reset the second Open would
	// leave `closed` sticky and the very next Send returns
	// net.ErrClosed. Pinned by `wgbridge_native: peer(...) -
	// Failed to send handshake initiation: use of closed network
	// connection` log line in reference/log.txt from the
	// diagnosis (VC=9).
	b.closed = false
	lc := makeListenConfig()
	port := int(uport)
	pc4, err := lc.ListenPacket(context.Background(),
		"udp4", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, 0, fmt.Errorf("protectingBind: udp4 listen: %w", err)
	}
	v4 := pc4.(*net.UDPConn)
	if port == 0 {
		port = v4.LocalAddr().(*net.UDPAddr).Port
	}
	// v6 is best-effort. If the host has no IPv6 stack we still
	// want the tunnel up (joiner-side WG over v4 works fine).
	var v6 *net.UDPConn
	pc6, v6err := lc.ListenPacket(context.Background(),
		"udp6", fmt.Sprintf(":%d", port))
	if v6err == nil {
		v6 = pc6.(*net.UDPConn)
	}
	b.v4 = v4
	b.v6 = v6
	b.port = uint16(port)
	fns := []conn.ReceiveFunc{b.makeReceive(v4)}
	if v6 != nil {
		fns = append(fns, b.makeReceive(v6))
	}
	return fns, b.port, nil
}

// makeReceive returns a ReceiveFunc that reads a single datagram
// per call. wireguard-go's contract: pack up to one datagram into
// packets[0], write the length to sizes[0], the endpoint to eps[0],
// return the count.
func (b *protectingBind) makeReceive(pc *net.UDPConn) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if len(packets) == 0 {
			return 0, errors.New("protectingBind: empty packets slice")
		}
		n, addr, err := pc.ReadFromUDPAddrPort(packets[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = &conn.StdNetEndpoint{AddrPort: addr}
		return 1, nil
	}
}

func (b *protectingBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	var firstErr error
	if b.v4 != nil {
		if err := b.v4.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		b.v4 = nil
	}
	if b.v6 != nil {
		if err := b.v6.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		b.v6 = nil
	}
	return firstErr
}

// SetMark is a no-op. Android's protect() handles the routing
// override; we don't need SO_MARK on top of it.
func (b *protectingBind) SetMark(mark uint32) error { return nil }

// BatchSize: one datagram per Receive/Send call. StdNetBind does
// up to 128 with GSO; we don't, and the joiner path is single-
// peer + low traffic, so the difference is invisible.
func (b *protectingBind) BatchSize() int { return 1 }

func (b *protectingBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	v4, v6, closed := b.v4, b.v6, b.closed
	b.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	se, ok := ep.(*conn.StdNetEndpoint)
	if !ok {
		return fmt.Errorf("protectingBind: unexpected endpoint type %T", ep)
	}
	addr := se.AddrPort
	var pc *net.UDPConn
	if addr.Addr().Is4() || addr.Addr().Is4In6() {
		pc = v4
	} else {
		pc = v6
	}
	if pc == nil {
		return fmt.Errorf("protectingBind: no socket for address family of %s",
			addr.Addr())
	}
	udpAddr := net.UDPAddrFromAddrPort(addr)
	for _, buf := range bufs {
		if _, err := pc.WriteToUDP(buf, udpAddr); err != nil {
			return err
		}
	}
	return nil
}

func (b *protectingBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &conn.StdNetEndpoint{AddrPort: ap}, nil
}

// newJoinerBind selects the protect-aware bind on Android.
func newJoinerBind() conn.Bind { return newProtectingBind() }
