// SPDX-License-Identifier: Apache-2.0
//
// JNI surface for libwgbridge_native.so.  Adapts JNI types
// (jstring, jint) to the cgo-friendly types the //export
// functions in api.go expect.  Pattern lifted from
// wireguard-android's tunnel/tools/libwg-go/jni.c.
//
// Each Java_* function:
//   1. Converts jstring inputs to (char*, length) pairs.
//   2. Calls the matching //export function from api.go.
//   3. Converts the C return value back to a JNI type.
//   4. Frees any heap allocations the Go side returned (Go's
//      C.CString returns malloc()'d memory we own here).

#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include "jni_android.h"

// Forward declarations of the //export functions in api.go +
// listeners.go.  cgo generates `_cgo_export.h` we COULD include,
// but listing them explicitly makes the C↔Go contract visible to
// a reader of jni_android.c without a build artefact in scope.
extern char *wgbridgeVersion(void);
extern int wgbridgeNew(const char *localAddr, long localAddrLen, int mtu, int listenPort);
extern int wgbridgeNewWithTunFd(int fd);
extern int wgbridgeConfigureUAPI(int handle, const char *uapi, long uapi_len);
extern char *wgbridgeSnapshotUAPI(int handle);
extern int wgbridgeSetFdProtector(int handle);
extern void wgbridgeClose(int handle);
// Listener exports — see wgbridge_native/listeners.go.
extern int wgbridgeListenTCP(int handle, int port);
extern int wgbridgeListenUDP(int handle, int port);
extern int wgbridgeDialTCP(int handle, const char *dest, long destLen);
extern int wgbridgeInstallTCPForwarder(int handle);
extern int wgbridgeInstallUDPForwarder(int handle);
extern int wgbridgeUDPFlowWrite(int flowHandle, char *buf, int bufLen);
extern void wgbridgeUDPFlowClose(int flowHandle);
extern int wgbridgePingV4(int handle, const char *dest, int destLen, int timeoutMs);
extern int wgbridgeInstallHostForwarder(int handle, const char *peerSubnet, int peerSubnetLen);
// D4.J3 — joiner-N shared netstack exports.  See
// wgbridge_native/joiner_n_exports.go for the Go side + return
// code documentation.
extern int wgbridgeSharedStackNew(int mtu);
extern void wgbridgeSharedStackClose(int handle);
extern int wgbridgeSharedStackAttachKernelTun(int handle, int fd, int mtu);
extern int wgbridgeSharedStackOpenJoiner(int stackHandle,
                                          const char *peerAllowedCsv, long peerAllowedLen,
                                          const char *interfaceAddrsCsv, long interfaceAddrsLen,
                                          int mtu);
extern int wgbridgeTCPRead(int connHandle, char *buf, int bufLen);
extern int wgbridgeTCPWrite(int connHandle, char *buf, int bufLen);
extern void wgbridgeTCPClose(int connHandle);
extern int wgbridgeUDPSendTo(int listenerHandle,
                              const char *peerAddr, long peerAddrLen,
                              char *buf, int bufLen);
extern void wgbridgeCloseListener(int listenerHandle);

// ──────────────────────────────────────────────────────────────
// JNI_OnLoad — cache JavaVM + the static dispatch method IDs.
//
// We need the JavaVM to be able to AttachCurrentThread from Go's
// accept-loop goroutines (those threads aren't known to the JVM
// otherwise).  We need the method IDs cached because FindClass /
// GetStaticMethodID can only be called from a JVM-attached thread,
// and doing it on every dispatch would be slow + race-prone.

static JavaVM *g_vm = NULL;
static jclass g_wgbn_class = NULL;       // GlobalRef to WgBridgeNative.class
static jmethodID g_on_tcp_accept_id = NULL;
static jmethodID g_on_udp_datagram_id = NULL;
static jmethodID g_on_tcp_forwarded_accept_id = NULL;
static jmethodID g_on_udp_forwarded_flow_id = NULL;
// PS11: protectFd is called from the protect-aware conn.Bind on the
// joiner path, BEFORE every UDP socket bind, so the OS uses the
// underlying network instead of routing the encrypted UDP back into
// the tun and storming the device.  Returns true on success.
static jmethodID g_protect_fd_id = NULL;

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    JNIEnv *env;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }
    g_vm = vm;
    jclass local = (*env)->FindClass(env, "com/gutschke/wgrtc/data/WgBridgeNative");
    if (local == NULL) return JNI_ERR;
    g_wgbn_class = (*env)->NewGlobalRef(env, local);
    (*env)->DeleteLocalRef(env, local);
    if (g_wgbn_class == NULL) return JNI_ERR;
    g_on_tcp_accept_id = (*env)->GetStaticMethodID(env, g_wgbn_class,
        "onTcpAccept", "(IILjava/lang/String;Ljava/lang/String;)V");
    g_on_udp_datagram_id = (*env)->GetStaticMethodID(env, g_wgbn_class,
        "onUdpDatagram", "(ILjava/lang/String;Ljava/lang/String;[B)V");
    g_on_tcp_forwarded_accept_id = (*env)->GetStaticMethodID(env, g_wgbn_class,
        "onTcpForwardedAccept",
        "(IILjava/lang/String;Ljava/lang/String;)V");
    g_on_udp_forwarded_flow_id = (*env)->GetStaticMethodID(env, g_wgbn_class,
        "onUdpForwardedFlow",
        "(IILjava/lang/String;Ljava/lang/String;[B)V");
    g_protect_fd_id = (*env)->GetStaticMethodID(env, g_wgbn_class,
        "protectFd", "(I)Z");
    if (g_on_tcp_accept_id == NULL || g_on_udp_datagram_id == NULL ||
        g_on_tcp_forwarded_accept_id == NULL ||
        g_on_udp_forwarded_flow_id == NULL ||
        g_protect_fd_id == NULL) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}

// Helper: attach the current thread to the JVM if it isn't
// already.  Returns 1 if we attached (caller should detach on
// return), 0 if it was already attached.  Sets *env_out on
// success; returns -1 on failure (env_out untouched).
static int attach_if_needed(JNIEnv **env_out)
{
    if (g_vm == NULL) return -1;
    int status = (*g_vm)->GetEnv(g_vm, (void **)env_out, JNI_VERSION_1_6);
    if (status == JNI_OK) return 0;
    if (status == JNI_EDETACHED) {
        if ((*g_vm)->AttachCurrentThread(g_vm, env_out, NULL) != JNI_OK) {
            return -1;
        }
        return 1;
    }
    return -1;
}

void wgbridge_dispatch_tcp_accept(int listenerID, int connID,
                                   const char *peer, const char *local)
{
    if (g_wgbn_class == NULL || g_on_tcp_accept_id == NULL) return;
    JNIEnv *env;
    int attached = attach_if_needed(&env);
    if (attached < 0) return;
    jstring jPeer = (*env)->NewStringUTF(env, peer ? peer : "");
    jstring jLocal = (*env)->NewStringUTF(env, local ? local : "");
    (*env)->CallStaticVoidMethod(env, g_wgbn_class, g_on_tcp_accept_id,
                                  (jint)listenerID, (jint)connID, jPeer, jLocal);
    // A pending exception (e.g. RuntimeException raised by the
    // Java callback) would leave the next JNI call in an
    // undefined state.  Clear and continue — the Java side has
    // already logged via Log.e by the time we get here.
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }
    (*env)->DeleteLocalRef(env, jPeer);
    (*env)->DeleteLocalRef(env, jLocal);
    if (attached) (*g_vm)->DetachCurrentThread(g_vm);
}

void wgbridge_dispatch_tcp_forwarded_accept(int forwarderID, int connID,
                                             const char *peer, const char *origDest)
{
    if (g_wgbn_class == NULL || g_on_tcp_forwarded_accept_id == NULL) return;
    JNIEnv *env;
    int attached = attach_if_needed(&env);
    if (attached < 0) return;
    jstring jPeer = (*env)->NewStringUTF(env, peer ? peer : "");
    jstring jOrigDest = (*env)->NewStringUTF(env, origDest ? origDest : "");
    (*env)->CallStaticVoidMethod(env, g_wgbn_class, g_on_tcp_forwarded_accept_id,
                                  (jint)forwarderID, (jint)connID, jPeer, jOrigDest);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }
    (*env)->DeleteLocalRef(env, jPeer);
    (*env)->DeleteLocalRef(env, jOrigDest);
    if (attached) (*g_vm)->DetachCurrentThread(g_vm);
}

void wgbridge_dispatch_udp_forwarded_flow(int forwarderID, int flowID,
                                           const char *peer, const char *origDest,
                                           const char *data, int dataLen)
{
    if (g_wgbn_class == NULL || g_on_udp_forwarded_flow_id == NULL) return;
    JNIEnv *env;
    int attached = attach_if_needed(&env);
    if (attached < 0) return;
    jstring jPeer = (*env)->NewStringUTF(env, peer ? peer : "");
    jstring jDest = (*env)->NewStringUTF(env, origDest ? origDest : "");
    jbyteArray jData = (*env)->NewByteArray(env, (jsize)dataLen);
    if (jData != NULL && dataLen > 0 && data != NULL) {
        (*env)->SetByteArrayRegion(env, jData, 0, (jsize)dataLen, (const jbyte *)data);
    }
    (*env)->CallStaticVoidMethod(env, g_wgbn_class, g_on_udp_forwarded_flow_id,
                                  (jint)forwarderID, (jint)flowID, jPeer, jDest, jData);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }
    if (jData) (*env)->DeleteLocalRef(env, jData);
    (*env)->DeleteLocalRef(env, jPeer);
    (*env)->DeleteLocalRef(env, jDest);
    if (attached) (*g_vm)->DetachCurrentThread(g_vm);
}

// wgbridge_dispatch_protect_fd is the C side of PS11's protect
// callback.  Called from `protect_bind_android.go`'s ListenConfig
// Control hook BEFORE every UDP socket bind on the joiner path.
// Returns 1 if Java's `WgBridgeNative.protectFd(fd)` returned true
// (or if no protector is currently installed — see the Java side
// for that no-op semantic, which lets unit tests that don't go
// through a VpnService still bring wg-go up), 0 on hard failure.
int wgbridge_dispatch_protect_fd(int fd)
{
    if (g_wgbn_class == NULL || g_protect_fd_id == NULL) return 1;
    JNIEnv *env;
    int attached = attach_if_needed(&env);
    if (attached < 0) return 1;  // can't attach → don't block bind
    jboolean ok = (*env)->CallStaticBooleanMethod(env, g_wgbn_class,
        g_protect_fd_id, (jint)fd);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        ok = JNI_FALSE;
    }
    if (attached) (*g_vm)->DetachCurrentThread(g_vm);
    return ok ? 1 : 0;
}

void wgbridge_dispatch_udp_datagram(int listenerID,
                                     const char *peer, const char *local,
                                     const char *data, int dataLen)
{
    if (g_wgbn_class == NULL || g_on_udp_datagram_id == NULL) return;
    JNIEnv *env;
    int attached = attach_if_needed(&env);
    if (attached < 0) return;
    jstring jPeer = (*env)->NewStringUTF(env, peer ? peer : "");
    jstring jLocal = (*env)->NewStringUTF(env, local ? local : "");
    jbyteArray jData = (*env)->NewByteArray(env, (jsize)dataLen);
    if (jData != NULL && dataLen > 0 && data != NULL) {
        (*env)->SetByteArrayRegion(env, jData, 0, (jsize)dataLen, (const jbyte *)data);
    }
    (*env)->CallStaticVoidMethod(env, g_wgbn_class, g_on_udp_datagram_id,
                                  (jint)listenerID, jPeer, jLocal, jData);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }
    if (jData) (*env)->DeleteLocalRef(env, jData);
    (*env)->DeleteLocalRef(env, jPeer);
    (*env)->DeleteLocalRef(env, jLocal);
    if (attached) (*g_vm)->DetachCurrentThread(g_vm);
}

JNIEXPORT jstring JNICALL
Java_com_gutschke_wgrtc_data_WgBridgeNative_nativeVersion(JNIEnv *env, jclass cls)
{
    char *v = wgbridgeVersion();
    if (!v) return NULL;
    jstring ret = (*env)->NewStringUTF(env, v);
    // wgbridgeVersion returns C.CString-allocated memory.  We own
    // the lifetime here: copy into a jstring (NewStringUTF makes
    // its own copy) then free.
    free(v);
    return ret;
}

JNIEXPORT jint JNICALL
Java_com_gutschke_wgrtc_data_WgBridgeNative_nativeNew(JNIEnv *env, jclass cls, jstring localAddr, jint mtu, jint listenPort)
{
    if (localAddr == NULL) return -1;
    const char *addr_str = (*env)->GetStringUTFChars(env, localAddr, 0);
    if (addr_str == NULL) return -1;
    jsize addr_len = (*env)->GetStringUTFLength(env, localAddr);
    int rc = wgbridgeNew(addr_str, (long) addr_len, (int) mtu, (int) listenPort);
    (*env)->ReleaseStringUTFChars(env, localAddr, addr_str);
    return (jint) rc;
}

JNIEXPORT jint JNICALL
Java_com_gutschke_wgrtc_data_WgBridgeNative_nativeNewWithTunFd(JNIEnv *env, jclass cls, jint fd)
{
    return (jint) wgbridgeNewWithTunFd((int) fd);
}

JNIEXPORT jint JNICALL
Java_com_gutschke_wgrtc_data_WgBridgeNative_nativeSetFdProtector(JNIEnv *env, jclass cls, jint handle)
{
    return (jint) wgbridgeSetFdProtector((int) handle);
}

JNIEXPORT jint JNICALL
Java_com_gutschke_wgrtc_data_WgBridgeNative_nativeConfigureUAPI(JNIEnv *env, jclass cls, jint handle, jstring uapi)
{
    if (uapi == NULL) return -3;
    const char *uapi_str = (*env)->GetStringUTFChars(env, uapi, 0);
    if (uapi_str == NULL) return -3;
    jsize uapi_len = (*env)->GetStringUTFLength(env, uapi);
    int rc = wgbridgeConfigureUAPI((int) handle, uapi_str, (long) uapi_len);
    (*env)->ReleaseStringUTFChars(env, uapi, uapi_str);
    return (jint) rc;
}

JNIEXPORT jstring JNICALL
Java_com_gutschke_wgrtc_data_WgBridgeNative_nativeSnapshotUAPI(JNIEnv *env, jclass cls, jint handle)
{
    char *dump = wgbridgeSnapshotUAPI((int) handle);
    if (!dump) return NULL;
    jstring ret = (*env)->NewStringUTF(env, dump);
    free(dump);
    return ret;
}

JNIEXPORT void JNICALL
Java_com_gutschke_wgrtc_data_WgBridgeNative_nativeClose(JNIEnv *env, jclass cls, jint handle)
{
    wgbridgeClose((int) handle);
}

// ──────────────────────────────────────────────────────────────
// TCP / UDP listener JNI wrappers.

JNIEXPORT jint JNICALL
Java_com_gutschke_wgrtc_data_WgBridgeNative_nativeListenTcp(
    JNIEnv *env, jclass cls, jint handle, jint port)
{
    return (jint) wgbridgeListenTCP((int) handle, (int) port);
}

JNIEXPORT jint JNICALL
Java_com_gutschke_wgrtc_data_WgBridgeNative_nativeListenUdp(
    JNIEnv *env, jclass cls, jint handle, jint port)
{
    return (jint) wgbridgeListenUDP((int) handle, (int) port);
}

// **JNI critical-region hazard (do NOT revert this to
// GetPrimitiveArrayCritical).**  Earlier versions used
// `GetPrimitiveArrayCritical` for the array pointer.  That's
// faster (no copy, no malloc) BUT the JNI spec forbids any
// blocking operation inside the critical region — and
// `wgbridgeTCPRead`/`wgbridgeTCPWrite` block on `gonet.TCPConn`
// which suspends a Go goroutine and can wait on Java threads.
// While the critical region was open, ART's GC `ThreadFlip`
// couldn't run; every other `GetPrimitiveArrayCritical` (used by
// `Parcel.writeByteArray`, internal `Socket` allocation, etc.)
// blocked forever, ANR'ing the app.  Diagnosed from a
// bugreport thread dump showing main thread in
// `art::gc::Heap::IncrementDisableThreadFlip → WaitingForGcThreadFlip`.
//
// `GetByteArrayRegion` / `SetByteArrayRegion` copy bytes in/out,
// which adds one memcpy per call but doesn't pin the GC.  The
// cost is negligible compared to the network I/O we're about to
// do.  Use heap allocation for the staging buffer so very large
// reads (gonet TCP segment, ≤64KB) don't blow the C stack.
JNIEXPORT jint JNICALL
Java_com_gutschke_wgrtc_data_WgBridgeNative_nativeTcpRead(
    JNIEnv *env, jclass cls, jint connHandle, jbyteArray buf, jint bufLen)
{
    if (buf == NULL || bufLen <= 0) return 0;
    char *staging = (char *) malloc((size_t) bufLen);
    if (staging == NULL) return -1;
    int n = wgbridgeTCPRead((int) connHandle, staging, (int) bufLen);
    if (n > 0) {
        (*env)->SetByteArrayRegion(env, buf, 0, n, (const jbyte *) staging);
    }
    free(staging);
    return (jint) n;
}

JNIEXPORT jint JNICALL
Java_com_gutschke_wgrtc_data_WgBridgeNative_nativeTcpWrite(
    JNIEnv *env, jclass cls, jint connHandle, jbyteArray buf, jint bufLen)
{
    if (buf == NULL || bufLen <= 0) return 0;
    char *staging = (char *) malloc((size_t) bufLen);
    if (staging == NULL) return -1;
    (*env)->GetByteArrayRegion(env, buf, 0, bufLen, (jbyte *) staging);
    int n = wgbridgeTCPWrite((int) connHandle, staging, (int) bufLen);
    free(staging);
    return (jint) n;
}

JNIEXPORT void JNICALL
Java_com_gutschke_wgrtc_data_WgBridgeNative_nativeTcpClose(
    JNIEnv *env, jclass cls, jint connHandle)
{
    wgbridgeTCPClose((int) connHandle);
}

// See the critical-region hazard note above nativeTcpRead.
JNIEXPORT jint JNICALL
Java_com_gutschke_wgrtc_data_WgBridgeNative_nativeUdpSendTo(
    JNIEnv *env, jclass cls, jint listenerHandle, jstring peerAddr,
    jbyteArray buf, jint bufLen)
{
    if (peerAddr == NULL || buf == NULL || bufLen <= 0) return -1;
    const char *peer_str = (*env)->GetStringUTFChars(env, peerAddr, 0);
    if (peer_str == NULL) return -1;
    jsize peer_len = (*env)->GetStringUTFLength(env, peerAddr);
    char *staging = (char *) malloc((size_t) bufLen);
    if (staging == NULL) {
        (*env)->ReleaseStringUTFChars(env, peerAddr, peer_str);
        return -1;
    }
    (*env)->GetByteArrayRegion(env, buf, 0, bufLen, (jbyte *) staging);
    int n = wgbridgeUDPSendTo((int) listenerHandle, peer_str, (long) peer_len,
                              staging, (int) bufLen);
    free(staging);
    (*env)->ReleaseStringUTFChars(env, peerAddr, peer_str);
    return (jint) n;
}

JNIEXPORT void JNICALL
Java_com_gutschke_wgrtc_data_WgBridgeNative_nativeCloseListener(
    JNIEnv *env, jclass cls, jint listenerHandle)
{
    wgbridgeCloseListener((int) listenerHandle);
}

JNIEXPORT jint JNICALL
Java_com_gutschke_wgrtc_data_WgBridgeNative_nativeDialTcp(
    JNIEnv *env, jclass cls, jint handle, jstring dest)
{
    if (dest == NULL) return -3;
    const char *dest_str = (*env)->GetStringUTFChars(env, dest, 0);
    if (dest_str == NULL) return -3;
    jsize dest_len = (*env)->GetStringUTFLength(env, dest);
    int rc = wgbridgeDialTCP((int) handle, dest_str, (long) dest_len);
    (*env)->ReleaseStringUTFChars(env, dest, dest_str);
    return (jint) rc;
}

JNIEXPORT jint JNICALL
Java_com_gutschke_wgrtc_data_WgBridgeNative_nativeInstallTcpForwarder(
    JNIEnv *env, jclass cls, jint handle)
{
    return (jint) wgbridgeInstallTCPForwarder((int) handle);
}

JNIEXPORT jint JNICALL
Java_com_gutschke_wgrtc_data_WgBridgeNative_nativeInstallUdpForwarder(
    JNIEnv *env, jclass cls, jint handle)
{
    return (jint) wgbridgeInstallUDPForwarder((int) handle);
}

// See the critical-region hazard note above nativeTcpRead.
JNIEXPORT jint JNICALL
Java_com_gutschke_wgrtc_data_WgBridgeNative_nativeUdpFlowWrite(
    JNIEnv *env, jclass cls, jint flowHandle, jbyteArray buf, jint bufLen)
{
    if (buf == NULL || bufLen <= 0) return 0;
    char *staging = (char *) malloc((size_t) bufLen);
    if (staging == NULL) return -1;
    (*env)->GetByteArrayRegion(env, buf, 0, bufLen, (jbyte *) staging);
    int n = wgbridgeUDPFlowWrite((int) flowHandle, staging, (int) bufLen);
    free(staging);
    return (jint) n;
}

JNIEXPORT void JNICALL
Java_com_gutschke_wgrtc_data_WgBridgeNative_nativeUdpFlowClose(
    JNIEnv *env, jclass cls, jint flowHandle)
{
    wgbridgeUDPFlowClose((int) flowHandle);
}

JNIEXPORT jint JNICALL
Java_com_gutschke_wgrtc_data_WgBridgeNative_nativePingV4(
    JNIEnv *env, jclass cls, jint handle, jstring dest, jint timeoutMs)
{
    if (dest == NULL) return -3;
    const char *dest_str = (*env)->GetStringUTFChars(env, dest, 0);
    if (dest_str == NULL) return -3;
    jsize dest_len = (*env)->GetStringUTFLength(env, dest);
    int rc = wgbridgePingV4((int) handle, dest_str, (int) dest_len, (int) timeoutMs);
    (*env)->ReleaseStringUTFChars(env, dest, dest_str);
    return (jint) rc;
}

JNIEXPORT jint JNICALL
Java_com_gutschke_wgrtc_data_WgBridgeNative_nativeInstallHostForwarder(
    JNIEnv *env, jclass cls, jint handle, jstring peerSubnet)
{
    if (peerSubnet == NULL) return -4;
    const char *s = (*env)->GetStringUTFChars(env, peerSubnet, 0);
    if (s == NULL) return -4;
    jsize n = (*env)->GetStringUTFLength(env, peerSubnet);
    int rc = wgbridgeInstallHostForwarder((int) handle, s, (int) n);
    (*env)->ReleaseStringUTFChars(env, peerSubnet, s);
    return (jint) rc;
}

// ─── D4.J3 — shared-stack JNI surface ────────────────────────────
// Adapt the //export functions from joiner_n_exports.go to the
// Kotlin native-method signatures declared in WgBridgeNative.kt.

JNIEXPORT jint JNICALL
Java_com_gutschke_wgrtc_data_WgBridgeNative_nativeSharedStackNew(
    JNIEnv *env, jclass cls, jint mtu)
{
    (void) env; (void) cls;
    return (jint) wgbridgeSharedStackNew((int) mtu);
}

JNIEXPORT void JNICALL
Java_com_gutschke_wgrtc_data_WgBridgeNative_nativeSharedStackClose(
    JNIEnv *env, jclass cls, jint handle)
{
    (void) env; (void) cls;
    wgbridgeSharedStackClose((int) handle);
}

JNIEXPORT jint JNICALL
Java_com_gutschke_wgrtc_data_WgBridgeNative_nativeSharedStackAttachKernelTun(
    JNIEnv *env, jclass cls, jint handle, jint fd, jint mtu)
{
    (void) env; (void) cls;
    return (jint) wgbridgeSharedStackAttachKernelTun((int) handle, (int) fd, (int) mtu);
}

JNIEXPORT jint JNICALL
Java_com_gutschke_wgrtc_data_WgBridgeNative_nativeSharedStackOpenJoiner(
    JNIEnv *env, jclass cls,
    jint stackHandle,
    jstring peerAllowed,
    jstring interfaceAddrs,
    jint mtu)
{
    // Either string may be null when the caller has no routes for
    // that direction. Convert null to ("", 0) so the Go side's
    // parsePrefixCsv sees an empty list (no error).
    const char *pa_str = "";
    jsize pa_len = 0;
    if (peerAllowed != NULL) {
        pa_str = (*env)->GetStringUTFChars(env, peerAllowed, 0);
        if (pa_str == NULL) return -2;
        pa_len = (*env)->GetStringUTFLength(env, peerAllowed);
    }
    const char *ia_str = "";
    jsize ia_len = 0;
    if (interfaceAddrs != NULL) {
        ia_str = (*env)->GetStringUTFChars(env, interfaceAddrs, 0);
        if (ia_str == NULL) {
            if (peerAllowed != NULL) (*env)->ReleaseStringUTFChars(env, peerAllowed, pa_str);
            return -3;
        }
        ia_len = (*env)->GetStringUTFLength(env, interfaceAddrs);
    }
    int rc = wgbridgeSharedStackOpenJoiner(
        (int) stackHandle,
        pa_str, (long) pa_len,
        ia_str, (long) ia_len,
        (int) mtu);
    if (peerAllowed != NULL) (*env)->ReleaseStringUTFChars(env, peerAllowed, pa_str);
    if (interfaceAddrs != NULL) (*env)->ReleaseStringUTFChars(env, interfaceAddrs, ia_str);
    return (jint) rc;
}

