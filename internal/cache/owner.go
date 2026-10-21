// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"os"
	"reflect"
	"runtime"
	"strconv"
)

// ownedByCurrentUser reports whether fi belongs to the current user and is not
// writable by group or others. On Windows, where the cache lives in the user's
// profile and sharing is expressed through ACLs rather than mode bits, it
// always reports true.
//
// The owner is read from fi.Sys() by field name instead of through
// syscall.Stat_t, which only exists on Unix: a per-OS file pair would need
// build tags, and the branch coverage tool (gobco) type-checks every file of a
// package regardless of them.
func ownedByCurrentUser(fi os.FileInfo) bool {
	if runtime.GOOS == "windows" {
		return true
	}
	st := reflect.Indirect(reflect.ValueOf(fi.Sys()))
	if st.Kind() != reflect.Struct {
		return false
	}
	uid := st.FieldByName("Uid")
	// Compared as text: Getuid returns an int, the field is unsigned.
	return uid.IsValid() && uid.CanUint() && strconv.FormatUint(uid.Uint(), 10) == strconv.Itoa(os.Getuid()) && fi.Mode().Perm()&0o022 == 0
}
