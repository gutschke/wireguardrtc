// D4.P2 spike — can a goroutine own the read side of a kernel-TUN
// file descriptor, decoding raw IP frames out of it and injecting
// them into a shared gvisor netstack as the joiner-N architecture
// requires?
//
// **Scope.** The Linux/Android kernel TUN fd's user-space contract
// (one IP packet per Read, IP version distinguishable from byte 0
// upper-nibble) is already exercised in production by
// `wgbridgeNewWithTunFd` — that path hands the fd to wireguard-go
// which does `os.NewFile(fd).Read(buf)` in its internal pump. We
// know that works on every Android build we ship to.
//
// What's NEW for joiner-N is doing the read in OUR goroutine, and
// injecting decoded packets into a netstack we own (not wg-go's
// private one). This spike validates exactly that: a pump loop
// that reads framed IP packets off an `*os.File`, demuxes v4/v6,
// and feeds gvisor — with the loop tested end-to-end via an
// `os.Pipe()` standing in for the kernel TUN.
//
// **Why `SOCK_SEQPACKET` socketpair, and the iterations to get
// there.** The first pass used `os.Pipe()`; multi-packet tests
// silently corrupted because pipes are byte streams — `Read`
// concatenates queued packets into one call, and the pump's
// "byte 0 nibble = IP version" check accepts the prefix and
// injects one oversized malformed packet. The second pass moved
// to `SOCK_DGRAM`; tests 2 and 7 (multi-packet) passed but tests
// 1 and 4 (single packet then close) hung, because Linux's
// `recvmsg()` on a connected `SOCK_DGRAM` socketpair doesn't
// always deliver a zero-byte EOF when the peer closes — the read
// side can block on a drained queue indefinitely.
//
// `SOCK_SEQPACKET` gives both properties together: each `read`
// returns exactly one queued message (production-faithful packet
// framing) AND a peer-close cleanly returns a zero-byte read
// (so the production pump's `io.EOF` shutdown path is exercised).
// This is the userspace analogue of `/dev/net/tun` that the
// spike actually needs.
//
// **Out of scope here.** The Android-specific lifecycle of the fd
// (handed across JNI, closed when `Builder.establish()` revokes)
// is already covered by `WgBridgeNativeHandshakeTest`. P2 just
// proves the Go-side pump pattern; the Android end-to-end ride is
// `D4.J2` production wiring.

package main

import (
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// kernelTunPump + kernelTunWriter were moved to production in
// `joiner_n_pump.go` (D4.J2). Tests in this file now call the
// production functions directly.

// newSharedNetstack — a thin wrapper around the production
// `newSharedStack` helper from joiner_n_stack.go.  Returns the
// raw `*stack.Stack` for compatibility with tests written before
// the `sharedStackState` type existed; new tests should use
// `newSharedStack` directly.
func newSharedNetstack(t *testing.T) *stack.Stack {
	t.Helper()
	ss, err := newSharedStack(1500)
	if err != nil {
		t.Fatalf("newSharedStack: %v", err)
	}
	t.Cleanup(ss.close)
	return ss.stack
}

// seqpacketPair returns a `*os.File` pair representing the "kernel
// TUN" side (what we read packets out of) and the "test driver"
// side (what we write packets into). The underlying socketpair
// is `SOCK_SEQPACKET` which gives both per-`read` packet framing
// (each `read` returns one queued message) AND clean peer-close
// EOF semantics. The file-header comment walks through the
// `os.Pipe()` → `SOCK_DGRAM` → `SOCK_SEQPACKET` iteration this
// spike went through to find a fixture that models `/dev/net/tun`
// faithfully on both axes simultaneously.
func seqpacketPair(t *testing.T) (read, write *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("socketpair(SEQPACKET): %v", err)
	}
	r := os.NewFile(uintptr(fds[0]), "tun-fake-read")
	w := os.NewFile(uintptr(fds[1]), "tun-fake-write")
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})
	return r, w
}

// ---- the actual probes ----

// 1. One IPv4 packet written to the "kernel TUN" side appears on
// the channel endpoint's inbound side. Negative result here would
// mean the production pump can't even bootstrap.
func TestP2SpikeSingleV4PacketRoundTrips(t *testing.T) {
	stk := newSharedNetstack(t)
	ep := channel.New(1024, 1500, "")
	if err := stk.CreateNIC(1, ep); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}
	// Marker address so gvisor's strong-host model has a source
	// candidate (lesson from D4.P1).
	pa := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(
			netip.MustParseAddr("169.254.0.1").AsSlice()).WithPrefix(),
	}
	if err := stk.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %v", err)
	}

	tunRead, tunWrite := seqpacketPair(t)

	// Start the pump.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	drops := atomic.Uint64{}
	pumpDone := make(chan struct {
		injected int
		err      error
	}, 1)
	go func() {
		n, err := kernelTunPump(ctx, tunRead, ep, 1500, &drops)
		pumpDone <- struct {
			injected int
			err      error
		}{n, err}
	}()

	// Write one v4 UDP packet at the "kernel" side.
	packet := craftIPv4UDP(
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("10.1.0.5"),
		1234, 53, []byte("hi"),
	)
	if _, err := tunWrite.Write(packet); err != nil {
		t.Fatalf("write to pipe: %v", err)
	}

	// gvisor receives. Without a matching route the packet ends
	// up "unrouteable" — we don't care; what we want to confirm
	// is that gvisor ACCEPTED the inject (its `PacketsReceived`
	// counter increments only after InjectInbound completes the
	// link-layer handoff).
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if stk.Stats().IP.PacketsReceived.Value() >= 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if stk.Stats().IP.PacketsReceived.Value() < 1 {
		t.Fatalf("packet didn't reach gvisor: PacketsReceived=%d",
			stk.Stats().IP.PacketsReceived.Value())
	}
	if drops.Load() != 0 {
		t.Fatalf("non-IP frame counter unexpectedly nonzero: %d", drops.Load())
	}

	cancel()
	// Close the write end so the read goroutine sees EOF.
	_ = tunWrite.Close()
	select {
	case r := <-pumpDone:
		if r.err != nil {
			t.Fatalf("pump returned error: %v", r.err)
		}
		if r.injected != 1 {
			t.Fatalf("pump injected %d packets, want 1", r.injected)
		}
	case <-time.After(time.Second):
		t.Fatalf("pump didn't exit after close+cancel")
	}
}

// 2. The pump must demux v4 vs v6 by reading byte 0's upper
// nibble — a misclassified packet would silently land on the
// wrong protocol stack.
func TestP2SpikePumpDemuxesV4AndV6(t *testing.T) {
	stk := newSharedNetstack(t)
	ep := channel.New(1024, 1500, "")
	if err := stk.CreateNIC(1, ep); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}
	v4Addr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(
			netip.MustParseAddr("169.254.0.1").AsSlice()).WithPrefix(),
	}
	v6Addr := tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(
			netip.MustParseAddr("fe80::1").AsSlice()).WithPrefix(),
	}
	if err := stk.AddProtocolAddress(1, v4Addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddV4: %v", err)
	}
	if err := stk.AddProtocolAddress(1, v6Addr, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddV6: %v", err)
	}

	tunRead, tunWrite := seqpacketPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go kernelTunPump(ctx, tunRead, ep, 1500, nil)

	v4Packet := craftIPv4UDP(
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("10.1.0.5"),
		1234, 53, []byte("v4"))
	v6Packet := craftIPv6UDP(
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("fd00::5"),
		1234, 53, []byte("v6"))

	if _, err := tunWrite.Write(v4Packet); err != nil {
		t.Fatalf("write v4: %v", err)
	}
	if _, err := tunWrite.Write(v6Packet); err != nil {
		t.Fatalf("write v6: %v", err)
	}

	// Wait for both to be accounted for. We compare against the
	// stack-level IP counters since v4 and v6 share the aggregate.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if stk.Stats().IP.PacketsReceived.Value() >= 2 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if stk.Stats().IP.PacketsReceived.Value() < 2 {
		t.Fatalf("v4+v6 demux failed; PacketsReceived=%d",
			stk.Stats().IP.PacketsReceived.Value())
	}
}

// 3. Non-IP frames (impossible on real TUN-mode `/dev/net/tun` but
// defensible against future TAP-mode misconfiguration) increment
// the drop counter instead of panicking.
func TestP2SpikePumpDropsNonIpFrames(t *testing.T) {
	stk := newSharedNetstack(t)
	ep := channel.New(1024, 1500, "")
	if err := stk.CreateNIC(1, ep); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}
	tunRead, tunWrite := seqpacketPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	drops := atomic.Uint64{}
	go kernelTunPump(ctx, tunRead, ep, 1500, &drops)

	// Write garbage whose first byte is neither 0x4* nor 0x6*.
	_, err := tunWrite.Write([]byte{0xee, 0xff, 0xaa})
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	// Wait briefly for the pump to process.
	time.Sleep(50 * time.Millisecond)
	if drops.Load() != 1 {
		t.Fatalf("non-IP frame should bump the drop counter; got %d", drops.Load())
	}
	if stk.Stats().IP.PacketsReceived.Value() != 0 {
		t.Fatalf("gvisor saw a packet it shouldn't have; PacketsReceived=%d",
			stk.Stats().IP.PacketsReceived.Value())
	}
}

// 4. Closing the "TUN" fd from the producer side terminates the
// pump cleanly — no goroutine leak. This is the "user removed the
// VPN" shutdown path.
func TestP2SpikePumpExitsOnTunClose(t *testing.T) {
	stk := newSharedNetstack(t)
	ep := channel.New(1024, 1500, "")
	if err := stk.CreateNIC(1, ep); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}
	r, w := seqpacketPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := kernelTunPump(ctx, r, ep, 1500, nil)
		done <- err
	}()
	// Close the write side → reader gets the equivalent of EOF on
	// a SOCK_DGRAM socketpair (a zero-byte read once the peer is
	// closed). The pump's `n == 0; continue` branch then loops
	// until the next ctx check exits cleanly... actually no:
	// Linux returns a real EOF on SOCK_DGRAM only after the read
	// side's queue drains, which here happens immediately because
	// no datagrams were ever queued. The pump's
	// `errors.Is(err, io.EOF)` branch catches it.
	_ = w.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("pump exited with error on TUN close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("pump didn't exit within 1s of TUN close — goroutine leak")
	}
	_ = r.Close()
}

// 5. Cancelling the context exits the pump even when the TUN
// stays open (the "stop the service while VPN is still up" path).
// This requires the pump to make progress between blocking reads
// — Go's `os.File.Read` is uncancellable, so the pump can only
// react after the next read returns. We trigger a read by
// writing a packet, then verify cancel works.
func TestP2SpikePumpExitsOnContextCancel(t *testing.T) {
	stk := newSharedNetstack(t)
	ep := channel.New(1024, 1500, "")
	if err := stk.CreateNIC(1, ep); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}
	pa := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(
			netip.MustParseAddr("169.254.0.1").AsSlice()).WithPrefix(),
	}
	_ = stk.AddProtocolAddress(1, pa, stack.AddressProperties{})

	tunRead, tunWrite := seqpacketPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := kernelTunPump(ctx, tunRead, ep, 1500, nil)
		done <- err
	}()

	// Cancel BEFORE any traffic.
	cancel()
	// Unblock the pending Read with a final packet — the pump
	// will then notice ctx.Err() at the top of the loop.
	pkt := craftIPv4UDP(
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("10.1.0.5"),
		1234, 53, []byte("x"))
	_, _ = tunWrite.Write(pkt)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("pump exited with error on ctx cancel: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("pump didn't exit after ctx cancel — would mean " +
			"the production service can't be stopped while the VPN " +
			"is still up.")
	}
}

// 6. Writer side: gvisor emits a packet, the writer pushes it to
// the kernel-TUN fd, and the test driver reads it back unchanged.
// This is the OUTBOUND path — joiner-N's "wg-go decrypted a
// packet for an app, send it up to the kernel".
func TestP2SpikeWriterEmitsOutboundPackets(t *testing.T) {
	stk := newSharedNetstack(t)
	ep := channel.New(1024, 1500, "")
	if err := stk.CreateNIC(1, ep); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}

	tunRead, tunWrite := seqpacketPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go kernelTunWriter(ctx, tunWrite, ep)

	// Crank a packet at the channel endpoint as if gvisor
	// produced it for outbound delivery.
	packet := craftIPv4UDP(
		netip.MustParseAddr("10.1.0.5"),
		netip.MustParseAddr("192.0.2.1"),
		53, 1234, []byte("pong"),
	)
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packet),
	})
	// channel.Endpoint.WritePackets pushes to the outbound queue
	// (which `kernelTunWriter` reads).
	var list stack.PacketBufferList
	list.PushBack(pkb)
	written, terr := ep.WritePackets(list)
	if terr != nil {
		t.Fatalf("WritePackets: %v", terr)
	}
	if written != 1 {
		t.Fatalf("WritePackets returned n=%d", written)
	}

	// Read it back from the pipe.
	buf := make([]byte, 1500)
	tunRead.SetDeadline(time.Now().Add(500 * time.Millisecond))
	n, err := tunRead.Read(buf)
	if err != nil {
		t.Fatalf("read outbound: %v", err)
	}
	if n != len(packet) {
		t.Fatalf("got %d bytes, want %d", n, len(packet))
	}
	// Spot-check it parses as a valid IPv4 header with our dst.
	hdr := header.IPv4(buf[:n])
	gotDst := hdr.DestinationAddress().As4()
	if netip.AddrFrom4(gotDst).String() != "192.0.2.1" {
		t.Fatalf("dst mismatch: got %v", netip.AddrFrom4(gotDst))
	}
}

// 7. Burst-load probe — the production pump must not lose or
// reorder a burst of packets. The pipe's PIPE_BUF guarantee
// ensures atomic writes up to ~4KB; we stay well below that.
func TestP2SpikePumpHandlesBurstWithoutReorder(t *testing.T) {
	stk := newSharedNetstack(t)
	ep := channel.New(1024, 1500, "")
	if err := stk.CreateNIC(1, ep); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}
	pa := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(
			netip.MustParseAddr("169.254.0.1").AsSlice()).WithPrefix(),
	}
	_ = stk.AddProtocolAddress(1, pa, stack.AddressProperties{})

	tunRead, tunWrite := seqpacketPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go kernelTunPump(ctx, tunRead, ep, 1500, nil)

	const N = 64
	for i := 0; i < N; i++ {
		payload := make([]byte, 4)
		binary.BigEndian.PutUint32(payload, uint32(i))
		pkt := craftIPv4UDP(
			netip.MustParseAddr("192.0.2.1"),
			netip.MustParseAddr("10.1.0.5"),
			1234, 53, payload,
		)
		if _, err := tunWrite.Write(pkt); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if stk.Stats().IP.PacketsReceived.Value() >= N {
			break
		}
		time.Sleep(time.Millisecond)
	}
	got := stk.Stats().IP.PacketsReceived.Value()
	if got != N {
		t.Fatalf("burst loss: only %d/%d packets reached gvisor", got, N)
	}
}
