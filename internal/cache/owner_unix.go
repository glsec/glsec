// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cache

import (
	"os"
	"syscall"
)

// ownedByCurrentUser reports whether fi belongs to the current user and is not
// writable by group or others.
func ownedByCurrentUser(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid() && fi.Mode().Perm()&0o022 == 0
}
