//go:build !android

package main

import "log"

func hostFwdLog(format string, args ...interface{}) {
	log.Printf("[host-fwd] "+format, args...)
}
