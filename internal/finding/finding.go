// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package finding

type Severity string

const (
	Error Severity = "error"
	Warn  Severity = "warn"
	Info  Severity = "info"
)

type Finding struct {
	RuleID   string
	Severity Severity
	Job      string
	Message  string
	File     string
	Line     int
	Col      int
}

// Where a suppression comes from.
const (
	SourceInline     = "inline"
	SourceIgnoreFile = "ignore-file"
)

// Suppressed is a finding that a # glsec:ignore comment or a .glsec-ignore
// entry suppresses. Reports that have a suppressed state show it instead of
// dropping it without a trace (#834).
type Suppressed struct {
	Finding
	Source  string // SourceInline or SourceIgnoreFile
	Reason  string // empty when none was given
	Expires string // "YYYY-MM-DD", empty when it doesn't expire
}
