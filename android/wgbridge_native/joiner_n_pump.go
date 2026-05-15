// Joiner-N's kernel-TUN pump — moves IP packets between the
// kernel TUN fd (NIC 0 of the shared stack) and gvisor. Production
// versions of the functions originally drafted in
// `kernel_tun_pump_spike_test.go`.
//
// One goroutine per direction:
//
//   - Reader pump: `read()` from fd → demux v4/v6 → InjectInbound
//     into the NIC's channel endpoint.
//   - Writer pump: drain the channel endpoint's outbound queue →
//     write the raw IP packet to the fd.
//
// Both pumps cancel cleanly when:
//   - Their `ctx` is canceled (the joiner-N controller is
//     shutting down).
//   - The fd is closed by another goroutine (`Read` / `Write`
//     return `os.ErrClosed`).
//   - The shared stack is closed (channel endpoint is destroyed).

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// kernelTunPump reads framed IP packets off [src], demuxes by IP
// version, injects into [ep]'s inbound queue. Stops when [ctx] is
// canceled or [src] is closed (EOF / "file already closed" both
// normalised to nil return). Returns the count of injected
// packets and the final error if any.
//
// `dropCounter` (if non-nil) increments for each frame whose
// first nibble is neither 4 nor 6 — defensive against a TAP-mode
// fd misconfiguration that shouldn't be possible on a TUN device
// but is cheap to count.
func kernelTunPump(
	ctx context.Context,
	src *os.File,
	ep *channel.Endpoint,
	mtu int,
	dropCounter *atomic.Uint64,
) (int, error) {
	buf := make([]byte, mtu)
	injected := 0
	for {
		if ctx.Err() != nil {
			return injected, nil
		}
		n, err := src.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
				return injected, nil
			}
			return injected, err
		}
		if n == 0 {
			continue
		}
		var proto tcpip.NetworkProtocolNumber
		switch buf[0] >> 4 {
		case 4:
			proto = header.IPv4ProtocolNumber
		case 6:
			proto = header.IPv6ProtocolNumber
		default:
			if dropCounter != nil {
				dropCounter.Add(1)
			}
			continue
		}
		// Copy into a fresh buffer — InjectInbound retains the
		// underlying memory beyond this iteration.
		pktBytes := make([]byte, n)
		copy(pktBytes, buf[:n])
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(pktBytes),
		})
		ep.InjectInbound(proto, pkt)
		pkt.DecRef()
		injected++
	}
}

// kernelTunWriter drains [ep]'s outbound queue and writes each
// packet to [dst]. Stops when [ctx] is canceled or [dst] is
// closed.
func kernelTunWriter(
	ctx context.Context,
	dst *os.File,
	ep *channel.Endpoint,
) (int, error) {
	written := 0
	for {
		if ctx.Err() != nil {
			return written, nil
		}
		pkt := ep.ReadContext(ctx)
		if pkt == nil {
			return written, nil // context canceled
		}
		v := pkt.ToView()
		raw := make([]byte, v.Size())
		_, _ = v.Read(raw)
		v.Release()
		pkt.DecRef()
		if _, err := dst.Write(raw); err != nil {
			if errors.Is(err, os.ErrClosed) {
				return written, nil
			}
			return written, err
		}
		written++
	}
}

// kernelTunPumpHandle is returned from [attachKernelTunPump] so
// callers can stop both pump goroutines + close the fd in one
// call. Goroutine leaks would be a serious bug — joiner-N
// reconfigures swap pumps on every `Builder.establish()` rebuild,
// so any leak compounds fast.
type kernelTunPumpHandle struct {
	cancel context.CancelFunc
	done   chan struct{}
	file   *os.File

	once       sync.Once
	stopErr    error
}

// Stop cancels both pump goroutines and closes the fd. Safe to
// call from multiple goroutines; only the first invocation does
// work, subsequent calls return the cached error.
func (h *kernelTunPumpHandle) Stop() error {
	h.once.Do(func() {
		h.cancel()
		// Closing the file unblocks any in-progress Read on the
		// reader goroutine — `os.File.Read` is not ctx-cancellable
		// so we need this explicit poke.
		if err := h.file.Close(); err != nil &&
			!errors.Is(err, os.ErrClosed) {
			h.stopErr = err
		}
		// Wait for both pumps to drain.
		<-h.done
	})
	return h.stopErr
}

// attachKernelTunPump wires a kernel TUN fd to the shared stack:
// allocates NIC 1 via `attachKernelTunNic`, wraps [fd] in an
// `*os.File`, and starts the reader + writer pump goroutines.
// Returns a handle that the caller uses to stop the pumps + close
// the fd.
//
// The pumps take OWNERSHIP of [fd]. The caller MUST NOT close it
// directly; that's [Stop]'s job.
//
// Errors:
//   - "shared stack closed" — caller's stack handle is already torn down.
//   - "kernel-TUN NIC already attached" — only one TUN per stack.
//   - "invalid fd" — negative fd or syscall-level error.
func attachKernelTunPump(ss *sharedStackState, fd int, mtu int) (*kernelTunPumpHandle, error) {
	if fd < 0 {
		return nil, fmt.Errorf("attachKernelTunPump: invalid fd %d", fd)
	}
	if ss == nil {
		return nil, fmt.Errorf("attachKernelTunPump: nil shared stack")
	}
	_, ep, err := ss.attachKernelTunNic()
	if err != nil {
		return nil, fmt.Errorf("attachKernelTunPump: %w", err)
	}
	// Set non-blocking BEFORE wrapping with os.NewFile.  Without
	// O_NONBLOCK, Go uses a raw `syscall.Read` that blocks in the
	// kernel — `file.Close()` on a sibling goroutine won't unblock
	// it, and `Stop()` deadlocks forever.  With O_NONBLOCK the
	// runtime registers the fd with the netpoller, which kicks
	// any pending poll-wait on close.  Wireguard-go's
	// `CreateUnmonitoredTUNFromFD` does the same thing for the
	// same reason.
	//
	// **Fd ownership on error**: until we've successfully wrapped
	// `fd` in `os.NewFile`, the fd is still the caller's, and the
	// Kotlin contract (`WgBridgeNative.kt`) says ownership transfers
	// only on a 0-return-code from `nativeSharedStackAttachKernelTun`.
	// Close on every pre-wrap failure path so a failed attach
	// doesn't permanently leak a TUN fd that the JVM thinks the
	// stack owns.  Post-wrap failures rely on `file.Close()`
	// instead.
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = ss.detachNic(reservedKernelTunNicID)
		_ = unix.Close(fd)
		return nil, fmt.Errorf("attachKernelTunPump: SetNonblock(%d): %w", fd, err)
	}
	// Wrap the fd. `os.NewFile` is the canonical way; it doesn't
	// take a copy, just a wrapper, so the *os.File owns the fd
	// lifecycle from here on.
	file := os.NewFile(uintptr(fd), "wgrtc-joiner-n-kernel-tun")
	if file == nil {
		// `NewFile` returns nil for invalid descriptors — most
		// likely closed already.  We can't construct an `os.File`
		// to close it; fall back to the raw syscall.
		_ = ss.detachNic(reservedKernelTunNicID)
		_ = unix.Close(fd)
		return nil, fmt.Errorf("attachKernelTunPump: os.NewFile returned nil for fd %d", fd)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	handle := &kernelTunPumpHandle{
		cancel: cancel,
		done:   done,
		file:   file,
	}

	// **Install the pump handle on the stack BEFORE spawning the
	// goroutines** (fix for the install-vs-close race uncovered
	// in review).  If a concurrent `close()` runs between
	// goroutine launch and the field write, `close` skips
	// pumpHandle.Stop() because `ss.pumpHandle` is still nil,
	// then closes the channel endpoint underneath the live
	// goroutines.  Setting the handle first AND re-checking
	// `ss.endpoints != nil` under the same lock makes the
	// startup atomic with respect to `close`.
	ss.mu.Lock()
	if ss.endpoints == nil {
		ss.mu.Unlock()
		// Stack closed concurrently — undo what we built.
		_ = file.Close()
		return nil, fmt.Errorf("attachKernelTunPump: shared stack closed during attach")
	}
	ss.pumpHandle = handle
	ss.mu.Unlock()

	// Run both pumps; signal completion when BOTH have returned.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = kernelTunPump(ctx, file, ep, mtu, nil)
	}()
	go func() {
		defer wg.Done()
		_, _ = kernelTunWriter(ctx, file, ep)
	}()
	go func() {
		wg.Wait()
		close(done)
	}()

	return handle, nil
}
