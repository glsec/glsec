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
