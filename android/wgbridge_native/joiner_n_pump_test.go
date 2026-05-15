// Production tests for `joiner_n_pump.go`. The lower-level pump
// functions (`kernelTunPump`, `kernelTunWriter`) are already
// exercised by the D4.P2 spike file using SOCK_SEQPACKET fixtures;
// this file focuses on `attachKernelTunPump` end-to-end:
//
//   - NIC 1 gets created on the shared stack.
//   - Packets written to the fd by a "kernel" peer flow through
//     the pump → gvisor → routed → out a joiner NIC's outbound
//     queue.
//   - `Stop()` cleanly halts both goroutines and closes the fd.

package main

import (
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// rawSeqpacketFds returns a pair of raw int fds connected via a
// `SOCK_SEQPACKET` Unix socketpair — same per-`read` framing /
// EOF semantics as `/dev/net/tun` (see the rationale in
// `kernel_tun_pump_spike_test.go`). The CALLER owns both fds and
// is responsible for closing them; the test passes one fd to
// `attachKernelTunPump` which takes ownership of that fd, and
// manages the other manually.
func rawSeqpacketFds(t *testing.T) (tunSide, peerSide int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	return fds[0], fds[1]
}

// writeRawPacket sends a raw IP packet on [fd] using `unix.Write`.
// Mirrors what a kernel TUN delivers — each Write becomes a single
// `read()` on the peer side.
func writeRawPacket(t *testing.T, fd int, pkt []byte) {
	t.Helper()
	for {
		n, err := unix.Write(fd, pkt)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			t.Fatalf("unix.Write(fd=%d): %v", fd, err)
		}
		if n != len(pkt) {
			t.Fatalf("unix.Write short: %d/%d", n, len(pkt))
		}
		return
	}
}

// 1. End-to-end smoke: attach pump → write a packet at the
// "kernel" side → confirm it reaches gvisor → confirm a routed
// joiner NIC sees it on its outbound queue. The full inbound
// production path in one assertion.
func TestJ2KernelTunPumpEndToEndRoutesToJoinerNic(t *testing.T) {
	ss, err := newSharedStack(1500)
	if err != nil {
		t.Fatalf("newSharedStack: %v", err)
	}
	defer ss.close()

	tunSide, peerSide := rawSeqpacketFds(t)
	// `peerSide` is the "kernel TUN side" we keep so we can write
	// packets at it.  Closed manually at end.
	defer unix.Close(peerSide)

	pump, err := attachKernelTunPump(ss, tunSide, 1500)
	if err != nil {
		t.Fatalf("attachKernelTunPump: %v", err)
	}
	// pump.Stop closes tunSide for us.
	defer func() {
		if err := pump.Stop(); err != nil {
			t.Fatalf("pump.Stop: %v", err)
		}
	}()

	// Joiner NIC + route — apps' 10.99.0.0/24 traffic should be
	// forwarded out the joiner NIC.
	joinerID, joinerEp, err := ss.attachNic()
	if err != nil {
		t.Fatalf("attachNic: %v", err)
	}
	if err := ss.addRoute(
		netip.MustParsePrefix("10.99.0.0/24"), joinerID,
	); err != nil {
		t.Fatalf("addRoute: %v", err)
	}

	// "Kernel TUN" delivers a packet.
	src := netip.MustParseAddr("192.0.2.1")
	dst := netip.MustParseAddr("10.99.0.5")
	writeRawPacket(t, peerSide, craftIPv4UDP(src, dst, 1234, 53, []byte("hi")))

	// Joiner NIC should see it on its outbound queue.
	deadline := time.Now().Add(500 * time.Millisecond)
	var pkt *stack.PacketBuffer
	for time.Now().Before(deadline) {
		if pkt = joinerEp.Read(); pkt != nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if pkt == nil {
		t.Fatalf("joiner NIC never saw the packet — pump or routing broken")
	}
	defer pkt.DecRef()
	v := pkt.ToView()
	raw := make([]byte, v.Size())
	_, _ = v.Read(raw)
	v.Release()
	hdr := header.IPv4(raw)
	gotDst := hdr.DestinationAddress().As4()
	if netip.AddrFrom4(gotDst) != dst {
		t.Fatalf("forwarded packet dst = %v, want %v",
			netip.AddrFrom4(gotDst), dst)
	}
}

// 2. Writer path: a joiner injects a packet (modeling wg-go
// delivering decrypted traffic) → routed to NIC 1 (kernel tun)
// → comes out the fd as a raw IP packet.
func TestJ2KernelTunPumpWritesBackToFd(t *testing.T) {
	ss, err := newSharedStack(1500)
	if err != nil {
		t.Fatalf("newSharedStack: %v", err)
	}
	defer ss.close()

	tunSide, peerSide := rawSeqpacketFds(t)
	defer unix.Close(peerSide)
	pump, err := attachKernelTunPump(ss, tunSide, 1500)
	if err != nil {
		t.Fatalf("attachKernelTunPump: %v", err)
	}
	defer pump.Stop()

	joinerID, joinerEp, _ := ss.attachNic()
	// Inbound: joiner → app means route "joiner interface addr"
	// → kernel tun NIC (1).
	if err := ss.addRoute(
		netip.MustParsePrefix("10.99.0.2/32"), reservedKernelTunNicID,
	); err != nil {
		t.Fatalf("addRoute: %v", err)
	}

	// Joiner injects a decrypted packet bound for the app.
	src := netip.MustParseAddr("10.99.0.5")
	dst := netip.MustParseAddr("10.99.0.2")
	raw := craftIPv4UDP(src, dst, 53, 1234, []byte("reply"))
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(raw),
	})
	joinerEp.InjectInbound(header.IPv4ProtocolNumber, pkb)
	pkb.DecRef()
	_ = joinerID

	// Read it off the kernel-tun fd's peer side.
	if err := unix.SetNonblock(peerSide, false); err != nil {
		t.Fatalf("SetNonblock: %v", err)
	}
	buf := make([]byte, 1500)
	deadline := time.Now().Add(500 * time.Millisecond)
	var n int
	for time.Now().Before(deadline) {
		// SetReadDeadline-equivalent — use a fresh non-blocking
		// read attempt with a sleep loop. SOCK_SEQPACKET doesn't
		// expose SO_RCVTIMEO via unix.Read directly; this is
		// simpler than restructuring around blocking.
		unix.SetNonblock(peerSide, true)
		var err error
		n, err = unix.Read(peerSide, buf)
		unix.SetNonblock(peerSide, false)
		if err == nil && n > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if n == 0 {
		t.Fatalf("writer didn't deliver the packet to the kernel fd")
	}
	hdr := header.IPv4(buf[:n])
	gotDst := hdr.DestinationAddress().As4()
	if netip.AddrFrom4(gotDst) != dst {
		t.Fatalf("dst = %v, want %v", netip.AddrFrom4(gotDst), dst)
	}
}

// 3. Lifecycle: Stop() is idempotent and unblocks any in-flight
// goroutine even after the peer closed early. We model that by
// closing the peer side BEFORE Stop, so the reader pump hits EOF
// before the cancel arrives.
func TestJ2PumpStopIsIdempotent(t *testing.T) {
	ss, _ := newSharedStack(1500)
	defer ss.close()
	tunSide, peerSide := rawSeqpacketFds(t)
	pump, err := attachKernelTunPump(ss, tunSide, 1500)
	if err != nil {
		t.Fatalf("attachKernelTunPump: %v", err)
	}
	// Close peer FIRST.
	unix.Close(peerSide)
	if err := pump.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	// Second Stop is a no-op.
	if err := pump.Stop(); err != nil {
		t.Fatalf("second Stop should be a no-op, got %v", err)
	}
}

// 4. attachKernelTunPump refuses an invalid fd cleanly.
func TestJ2AttachKernelTunPumpRejectsBadFd(t *testing.T) {
	ss, _ := newSharedStack(1500)
	defer ss.close()
	if _, err := attachKernelTunPump(ss, -1, 1500); err == nil {
		t.Fatalf("attachKernelTunPump(-1) should have errored")
	}
}

// 5. attachKernelTunPump refuses a second attach on the same
// stack — only one kernel TUN is supported per shared stack.
func TestJ2AttachKernelTunPumpRefusesDuplicates(t *testing.T) {
	ss, _ := newSharedStack(1500)
	defer ss.close()
	tunSide1, peerSide1 := rawSeqpacketFds(t)
	defer unix.Close(peerSide1)
	pump1, err := attachKernelTunPump(ss, tunSide1, 1500)
	if err != nil {
		t.Fatalf("first attach: %v", err)
	}
	defer pump1.Stop()

	tunSide2, peerSide2 := rawSeqpacketFds(t)
	defer unix.Close(tunSide2)
	defer unix.Close(peerSide2)
	if _, err := attachKernelTunPump(ss, tunSide2, 1500); err == nil {
		t.Fatalf("second attach to the same stack should have errored")
	}
}
