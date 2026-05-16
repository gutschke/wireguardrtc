// Tests for `joiner_n_bridge.go`. Exercises the `sharedNicLink`
// `tun.Device` adapter and the `openJoinerBridge` end-to-end
// open/route/close cycle. These tests DO open real wireguard-go
// devices — but with empty UAPI (no peers), so no handshake or
// encryption fires; we just want to confirm the lifecycle wiring
// is correct.

package main

import (
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// 1. The adapter's Read returns a packet that gvisor sent via
// the endpoint's WritePackets → Read path. Models a single
// outbound packet from gvisor reaching wireguard-go.
func TestJ2AdapterReadReceivesOutboundPacket(t *testing.T) {
	ss, _ := newSharedStack(1500)
	defer ss.close()
	nicID, ep, err := ss.attachNic()
	if err != nil {
		t.Fatalf("attachNic: %v", err)
	}
	link := newSharedNicLink(ss, nicID, ep, 1500)
	t.Cleanup(func() { _ = link.Close() })

	// Push a packet out via WritePackets — simulates gvisor
	// routing a packet to this NIC.
	raw := craftIPv4UDP(
		netip.MustParseAddr("10.99.0.5"),
		netip.MustParseAddr("192.0.2.1"),
		53, 1234, []byte("out"),
	)
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(raw),
	})
	var list stack.PacketBufferList
	list.PushBack(pkb)
	if n, terr := ep.WritePackets(list); terr != nil || n != 1 {
		t.Fatalf("WritePackets: n=%d err=%v", n, terr)
	}

	// wireguard-go's Read API: buf-of-bufs.
	bufs := [][]byte{make([]byte, 1500)}
	sizes := []int{0}
	// Run with a generous timeout — Read blocks on the channel,
	// so we use a goroutine to avoid hanging the test if the
	// adapter doesn't deliver.
	done := make(chan error, 1)
	go func() {
		_, err := link.Read(bufs, sizes, 0)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Read returned err: %v", err)
		}
		if sizes[0] == 0 {
			t.Fatalf("Read returned size 0")
		}
		hdr := header.IPv4(bufs[0][:sizes[0]])
		gotSrc := hdr.SourceAddress().As4()
		if netip.AddrFrom4(gotSrc).String() != "10.99.0.5" {
			t.Fatalf("src mismatch: got %v", netip.AddrFrom4(gotSrc))
		}
	case <-time.After(time.Second):
		t.Fatalf("Read didn't deliver within 1s — adapter or notify wiring broken")
	}
}

// 2. The adapter's Write injects into gvisor as if wg-go just
// decrypted the packet. Verified by watching gvisor's IP
// PacketsReceived counter.
func TestJ2AdapterWriteInjectsToGvisor(t *testing.T) {
	ss, _ := newSharedStack(1500)
	defer ss.close()
	nicID, ep, _ := ss.attachNic()
	link := newSharedNicLink(ss, nicID, ep, 1500)
	t.Cleanup(func() { _ = link.Close() })

	before := ss.stack.Stats().IP.PacketsReceived.Value()
	raw := craftIPv4UDP(
		netip.MustParseAddr("10.99.0.5"),
		netip.MustParseAddr("10.99.0.2"),
		53, 1234, []byte("dec"),
	)
	n, err := link.Write([][]byte{raw}, 0)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 1 {
		t.Fatalf("Write returned n=%d", n)
	}
	// Wait briefly for gvisor to process — InjectInbound is
	// async on a separate goroutine in some configurations.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if ss.stack.Stats().IP.PacketsReceived.Value() > before {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("gvisor never saw the injected packet (before=%d after=%d)",
		before, ss.stack.Stats().IP.PacketsReceived.Value())
}

// 3. The adapter's Close detaches the NIC from the shared
// stack — proving the link owns the NIC's lifecycle.
func TestJ2AdapterCloseDetachesNic(t *testing.T) {
	ss, _ := newSharedStack(1500)
	defer ss.close()
	nicID, ep, _ := ss.attachNic()
	link := newSharedNicLink(ss, nicID, ep, 1500)

	if _, ok := ss.stack.NICInfo()[nicID]; !ok {
		t.Fatalf("NIC %d not registered after attach", nicID)
	}
	if err := link.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, ok := ss.stack.NICInfo()[nicID]; ok {
		t.Fatalf("NIC %d still present after link.Close", nicID)
	}
	// Idempotent — second Close is a no-op.
	if err := link.Close(); err != nil {
		t.Fatalf("second Close should be no-op, got: %v", err)
	}
}

// 4. openJoinerBridge happy path — attaches a NIC, opens a
// wireguard-go device, programs routes, returns a valid bridge
// handle. Closing the bridge tears everything down.
func TestJ2OpenJoinerBridgeOpenAndClose(t *testing.T) {
	ss, _ := newSharedStack(1500)
	defer ss.close()
	// Pre-attach the kernel-TUN NIC so interface-addr routes
	// (which point at NIC 1) can resolve.
	if _, _, err := ss.attachKernelTunNic(); err != nil {
		t.Fatalf("attachKernelTunNic: %v", err)
	}

	handle, nicID, err := openJoinerBridge(
		ss,
		[]netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")},
		[]netip.Prefix{netip.MustParsePrefix("10.99.0.2/32")},
		1420,
	)
	if err != nil {
		t.Fatalf("openJoinerBridge: %v", err)
	}
	if handle <= 0 {
		t.Fatalf("openJoinerBridge returned bad handle %d", handle)
	}
	// Bridge should be findable via the existing handle map.
	if lookupHandle(handle) == nil {
		t.Fatalf("lookupHandle(%d) returned nil", handle)
	}
	// NIC should be registered.
	if _, ok := ss.stack.NICInfo()[nicID]; !ok {
		t.Fatalf("NIC %d not registered after open", nicID)
	}

	// Close — exactly the same path the JNI surface uses.
	bs := freeHandle(handle)
	if bs == nil {
		t.Fatalf("freeHandle returned nil")
	}
	bs.dev.Close()
	if _, ok := ss.stack.NICInfo()[nicID]; ok {
		t.Fatalf("NIC %d still present after dev.Close — link.Close didn't detach", nicID)
	}
}

// 5. End-to-end joiner-N flow at the adapter level. A
// "kernel-TUN" injected packet whose dst matches the joiner's
// AllowedIPs should arrive at the joiner adapter's Read side.
// This is the full forwarding path *minus* wireguard-go's
// encrypt step, validating that the routing + tun.Device adapter
// move bytes correctly.
func TestJ2EndToEndAppToJoinerAdapter(t *testing.T) {
	ss, _ := newSharedStack(1500)
	defer ss.close()
	// Stand-in for the kernel-TUN NIC: attach the reserved NIC
	// so we have a channel endpoint we can inject into.
	_, tunEp, err := ss.attachKernelTunNic()
	if err != nil {
		t.Fatalf("attachKernelTunNic: %v", err)
	}

	// Joiner via the production helper sans wg-go's Up call —
	// we don't want a real wireguard device for this test; just
	// the adapter wired to a NIC.
	nicID, ep, _ := ss.attachNic()
	link := newSharedNicLink(ss, nicID, ep, 1500)
	t.Cleanup(func() { _ = link.Close() })
	if err := ss.addRoute(
		netip.MustParsePrefix("10.99.0.0/24"), nicID,
	); err != nil {
		t.Fatalf("addRoute: %v", err)
	}

	// Inject as if the kernel TUN reader just handed gvisor this
	// packet.
	raw := craftIPv4UDP(
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("10.99.0.5"),
		1234, 53, []byte("hello"),
	)
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(raw),
	})
	tunEp.InjectInbound(header.IPv4ProtocolNumber, pkb)

	// The joiner adapter's Read should receive it.
	bufs := [][]byte{make([]byte, 1500)}
	sizes := []int{0}
	done := make(chan error, 1)
	go func() {
		_, err := link.Read(bufs, sizes, 0)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		hdr := header.IPv4(bufs[0][:sizes[0]])
		gotDst := hdr.DestinationAddress().As4()
		if netip.AddrFrom4(gotDst).String() != "10.99.0.5" {
			t.Fatalf("dst = %v, want 10.99.0.5", netip.AddrFrom4(gotDst))
		}
	case <-time.After(time.Second):
		t.Fatalf("end-to-end app→joiner didn't deliver — routing or adapter broken")
	}
}

// 6. Symmetric: a packet injected at the joiner adapter (modeling
// wg-go decrypted output) reaches the kernel-TUN endpoint.
func TestJ2EndToEndJoinerToApp(t *testing.T) {
	ss, _ := newSharedStack(1500)
	defer ss.close()
	_, tunEp, _ := ss.attachKernelTunNic()
	nicID, ep, _ := ss.attachNic()
	link := newSharedNicLink(ss, nicID, ep, 1500)
	t.Cleanup(func() { _ = link.Close() })

	// Inbound route: traffic for the joiner's app-side IP →
	// kernel-TUN.
	_ = ss.addRoute(netip.MustParsePrefix("10.99.0.2/32"), reservedKernelTunNicID)

	// Joiner side delivers a "decrypted" packet via Write.
	raw := craftIPv4UDP(
		netip.MustParseAddr("10.99.0.5"),
		netip.MustParseAddr("10.99.0.2"),
		53, 1234, []byte("reply"),
	)
	if _, err := link.Write([][]byte{raw}, 0); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Kernel-TUN endpoint should see it on its outbound side.
	deadline := time.Now().Add(500 * time.Millisecond)
	var got *stack.PacketBuffer
	for time.Now().Before(deadline) {
		if got = tunEp.Read(); got != nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if got == nil {
		t.Fatalf("kernel-TUN endpoint never saw the joiner's reply")
	}
	defer got.DecRef()
	v := got.ToView()
	pktBytes := make([]byte, v.Size())
	_, _ = v.Read(pktBytes)
	v.Release()
	hdr := header.IPv4(pktBytes)
	gotSrc := hdr.SourceAddress().As4()
	if netip.AddrFrom4(gotSrc).String() != "10.99.0.5" {
		t.Fatalf("src = %v, want 10.99.0.5", netip.AddrFrom4(gotSrc))
	}
	// Reference the channel.Endpoint type so the compiler doesn't
	// drop the import in CI builds that skip route-only paths.
	var _ = (*channel.Endpoint)(nil)
	_ = tcpip.NICID(0)
}

// Regression for v0.2.12 protect-bind fix: openJoinerBridge MUST
// use newJoinerBind() (the protect-aware bind on Android), not
// conn.NewDefaultBind().  Otherwise wireguard-go's outbound UDP
// socket is subject to VpnService routing — full-tunnel configs
// loop wg-go's own handshakes back through tun0 and the bridge
// stops handshaking after the first squeak-through.
//
// We can't easily black-box the bind choice (it's wired into
// device.Device, which doesn't expose the Bind it was given), so
// this test is a *source-lint* on joiner_n_bridge.go.  It is
// deliberately fragile: any change to the line that constructs
// the device must keep newJoinerBind() in the second argument.
func TestJoinerNBridgeUsesProtectAwareBind(t *testing.T) {
	raw, err := os.ReadFile("joiner_n_bridge.go")
	if err != nil {
		t.Fatalf("read joiner_n_bridge.go: %v", err)
	}
	codeOnly := stripGoLineComments(string(raw))
	if strings.Contains(codeOnly, "conn.NewDefaultBind()") {
		t.Fatalf("joiner_n_bridge.go must not use conn.NewDefaultBind() — " +
			"call newJoinerBind() instead so VpnService.protect() runs " +
			"on the bridge socket.  See v0.2.12 commit message.")
	}
	if !strings.Contains(codeOnly, "newJoinerBind()") {
		t.Fatalf("joiner_n_bridge.go must call newJoinerBind() to obtain " +
			"the protect-aware bind on Android.")
	}
}

// stripGoLineComments returns src with everything from "//" to
// end-of-line removed on every line.  Crude (doesn't handle /* */
// blocks, doesn't respect strings), but adequate for matching
// against well-known Go identifiers in joiner_n_bridge.go.
func stripGoLineComments(src string) string {
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}
