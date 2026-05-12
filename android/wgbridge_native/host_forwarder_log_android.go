//go:build android

package main

// #cgo LDFLAGS: -llog
// #include <android/log.h>
// #include <stdlib.h>
import "C"

import (
	"fmt"
	"unsafe"
)

func hostFwdLog(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	cMsg := C.CString(msg)
	tag := C.CString("wgbridge_native")
	C.__android_log_write(4 /* INFO */, tag, cMsg)
	C.free(unsafe.Pointer(cMsg))
	C.free(unsafe.Pointer(tag))
}
