// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cache

import "os"

// ownedByCurrentUser always reports true on Windows, where the cache lives in
// the user's profile and ownership is expressed through ACLs, not mode bits.
func ownedByCurrentUser(os.FileInfo) bool { return true }
