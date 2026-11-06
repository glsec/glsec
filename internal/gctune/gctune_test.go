// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package gctune

import (
	"runtime/debug"
	"testing"
)

func percent() int {
	p := debug.SetGCPercent(-1)
	debug.SetGCPercent(p)
	return p
}

func TestHoldAndRelease(t *testing.T) {
	before := percent()
	t.Cleanup(func() {
		held.Store(false)
		debug.SetGCPercent(before)
	})

	debug.SetGCPercent(runPercent)
	held.Store(false)
	hold("")
	if got := percent(); got != startPercent {
		t.Errorf("after hold: GC percent %d, want %d", got, startPercent)
	}
	Release()
	if got := percent(); got != runPercent {
		t.Errorf("after Release: GC percent %d, want %d", got, runPercent)
	}
}

func TestExplicitGOGCWins(t *testing.T) {
	before := percent()
	t.Cleanup(func() {
		held.Store(false)
		debug.SetGCPercent(before)
	})

	debug.SetGCPercent(50)
	held.Store(false)
	hold("50")
	Release()
	if got := percent(); got != 50 {
		t.Errorf("GC percent %d, want the user's 50", got)
	}
}
