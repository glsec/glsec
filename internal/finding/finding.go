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
	// Origin is where the configuration is when the finding was moved to the
	// job that uses it from another file of the pipeline (#1154).
	Origin Origin
}

// Origin is a place in another file.
type Origin struct {
	File string
	Line int
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
