// Header shared between the Go //export side (which calls these
// dispatchers via cgo) and the C JNI wrappers (which define them
// for Android and stub them out for host builds).
//
// The implementations live in jni_android.c (Android, real JNI
// callbacks) and jni_other.c (host, no-op stubs that just discard
// the arguments so go test ./... and CI host builds still link).

#ifndef WGBRIDGE_NATIVE_JNI_ANDROID_H
#define WGBRIDGE_NATIVE_JNI_ANDROID_H

// Dispatch a TCP-accept event to the JVM.  Called from Go's
// acceptLoopTCP goroutine.  The C side AttachCurrentThread's so
// the goroutine OS thread can call into JNI safely; arguments
// are copied (CallStaticVoidMethod creates new local refs).
//
// Strings are UTF-8 C strings (NUL-terminated).  Caller owns
// them and frees after return.
void wgbridge_dispatch_tcp_accept(int listenerID, int connID,
                                   const char* peer, const char* local);

// Dispatch a UDP datagram receive to the JVM.  Same threading
// rules.  `data` is a binary payload of length `dataLen`; the C
// side copies it into a fresh Java byte[].
void wgbridge_dispatch_udp_datagram(int listenerID,
                                     const char* peer, const char* local,
                                     const char* data, int dataLen);

// Dispatch a forwarded TCP accept to the JVM.  Same threading
// rules as the listener accept, but the second string is the
// ORIGINAL DESTINATION the joiner intended to reach (rather
// than our listener's bind address).  The forwarder caught a
// SYN to some address; this callback hands the connection +
// destination to the Kotlin side so it can open the outbound
// socket via the EgressSelector.
void wgbridge_dispatch_tcp_forwarded_accept(int forwarderID, int connID,
                                             const char* peer,
                                             const char* origDest);

// Dispatch a forwarded UDP datagram to the JVM.  Fires per
// datagram (not per-flow): the first datagram in a new flow
// triggers the flow's lifecycle on the Kotlin side; subsequent
// ones are routed by flowID.  The Kotlin handler keeps a
// per-flow OS DatagramSocket and idle timer.
void wgbridge_dispatch_udp_forwarded_flow(int forwarderID, int flowID,
                                           const char* peer,
                                           const char* origDest,
                                           const char* data, int dataLen);

#endif // WGBRIDGE_NATIVE_JNI_ANDROID_H
