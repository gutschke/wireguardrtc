//go:build android

// SPDX-License-Identifier: Apache-2.0
//
// Android logger — forwards wireguard-go's Verbosef / Errorf to
// logcat via __android_log_write. Without this, wireguard-go's
// internal log output (handshake events, peer-state changes,
// failure modes) disappears into Go's default `log` package which
// on Android writes to stderr → /dev/null. Logcat-bound logs
// give us actionable diagnostics on real-device failures.
//
// Pattern lifted from wireguard-android's
// `tunnel/tools/libwg-go/api-android.go` AndroidLogger.

package main

// #cgo LDFLAGS: -llog
// #include <android/log.h>
// #include <stdlib.h>
import "C"

import (
	"fmt"
	"unsafe"

	"golang.zx2c4.com/wireguard/device"
)

type androidLogger struct {
	prefix *C.char
	level C.int
}

func newAndroidLogger(level C.int, tag string) *androidLogger {
	return &androidLogger{prefix: C.CString(tag), level: level}
}

func (l *androidLogger) Printf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	cMsg := C.CString(msg)
	C.__android_log_write(l.level, l.prefix, cMsg)
	C.free(unsafe.Pointer(cMsg))
}

// makeWgLogger returns a wireguard-go Logger backed by Android's
// logcat. Verbosef → ANDROID_LOG_INFO (4); Errorf → ERROR (6).
func makeWgLogger() *device.Logger {
	verbose := newAndroidLogger(4 /* ANDROID_LOG_INFO */, "wgbridge_native")
	errLogger := newAndroidLogger(6 /* ANDROID_LOG_ERROR */, "wgbridge_native")
	return &device.Logger{
		Verbosef: verbose.Printf,
		Errorf: errLogger.Printf,
	}
}
