// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

// Package docs embeds the per-rule documentation (docs/rules/GLxxx.md) that
// glsec explain and glsec list print.
package docs

import "embed"

//go:embed rules
var FS embed.FS
