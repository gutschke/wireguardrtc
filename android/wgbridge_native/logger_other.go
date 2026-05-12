//go:build !android

// Fallback logger for non-Android builds (host `go test`,
// `go build` checks). Uses wireguard-go's stock device.NewLogger
// which writes via Go's `log` package. Real builds always use
// the android variant; this is only here so `go test ./...` on
// the dev host doesn't error out on an undefined symbol.

package main

import "golang.zx2c4.com/wireguard/device"

func makeWgLogger() *device.Logger {
	return device.NewLogger(device.LogLevelVerbose, "wgbridge_native: ")
}
