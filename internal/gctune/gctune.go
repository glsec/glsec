// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

// Package gctune keeps the garbage collector quiet while the program starts.
//
// Initialising the rules compiles hundreds of regexps. They stay live until the
// process exits, so a collection during that phase reclaims nothing, yet those
// collections cost about a quarter of the CPU time of a typical scan.
//
// Only cmd/glsec imports this package, so a program that uses the rules keeps
// its own GC settings. Go initialises packages in import path order once their
// imports are ready, so this one runs before internal/redact and rules; the
// package name keeps it that way, and cmd/glsec has a test for it.
package gctune

import (
	"os"
	"runtime/debug"
	"sync/atomic"
)

const (
	startPercent = 1600
	runPercent   = 100
)

var held atomic.Bool

func init() {
	hold(os.Getenv("GOGC"))
}

// hold relaxes the collector unless the user chose a GOGC.
func hold(gogc string) {
	if gogc == "" {
		debug.SetGCPercent(startPercent)
		held.Store(true)
	}
}

// Release returns the collector to its default for the scan, whose memory use
// grows with the pipeline.
func Release() {
	if held.CompareAndSwap(true, false) {
		debug.SetGCPercent(runPercent)
	}
}
