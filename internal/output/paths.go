// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package output

import "path/filepath"

// reportPath makes paths inside cwd portable without exposing the runner's
// directory: relative, with / separators also on Windows (#956). The bool
// identifies locations relative to the source root for SARIF. Outside paths
// retain their supplied spelling; no files are read.
func reportPath(file, cwd string) (string, bool) {
	if !filepath.IsAbs(file) {
		if filepath.IsLocal(file) {
			return filepath.ToSlash(file), true
		}
		return file, false
	}
	if cwd != "" {
		if rel, err := filepath.Rel(cwd, file); err == nil && filepath.IsLocal(rel) {
			return filepath.ToSlash(rel), true
		}
	}
	return file, false
}
