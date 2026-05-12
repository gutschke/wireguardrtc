//go:build !android

// Stub dispatchers for non-Android builds.  The real
// implementations live in jni_android.c and call into the JVM via
// JNI; on host builds (`go test ./...`, CI sanity-check
// compiles) there is no JVM, so the dispatchers just discard
// their arguments.  They MUST still link, though, because the
// Go-side //export listener functions (acceptLoopTCP,
// recvLoopUDP) call them unconditionally.
//
// Naming this file `_other.c` is purely human-readable; the
// `//go:build` line above is what controls cgo's inclusion
// rules.  Go's cgo treats top-of-file `//go:build` constraints
// in `.c` files just like in `.go` files since 1.17.

#include "jni_android.h"

void wgbridge_dispatch_tcp_accept(int listenerID, int connID,
                                   const char *peer, const char *local)
{
    (void) listenerID;
    (void) connID;
    (void) peer;
    (void) local;
}

void wgbridge_dispatch_udp_datagram(int listenerID,
                                     const char *peer, const char *local,
                                     const char *data, int dataLen)
{
    (void) listenerID;
    (void) peer;
    (void) local;
    (void) data;
    (void) dataLen;
}

void wgbridge_dispatch_tcp_forwarded_accept(int forwarderID, int connID,
                                              const char *peer, const char *origDest)
{
    (void) forwarderID;
    (void) connID;
    (void) peer;
    (void) origDest;
}

void wgbridge_dispatch_udp_forwarded_flow(int forwarderID, int flowID,
                                            const char *peer, const char *origDest,
                                            const char *data, int dataLen)
{
    (void) forwarderID;
    (void) flowID;
    (void) peer;
    (void) origDest;
    (void) data;
    (void) dataLen;
}
