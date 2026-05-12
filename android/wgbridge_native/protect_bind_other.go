//go:build !android

// Non-Android fallback: no protect() to call; just use the upstream
// StdNetBind. Keeps `go test ./...` building on the host without
// the cgo + JNI machinery the Android build needs.

package main

import "golang.zx2c4.com/wireguard/conn"

func newJoinerBind() conn.Bind { return conn.NewStdNetBind() }
