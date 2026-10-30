// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
)

// ScanError is a file glsec could not scan. The machine-readable reports
// carry it, so a failed scan doesn't read as a clean one (#809). File is empty
// for an error that belongs to no file.
type ScanError struct {
	File    string
	Message string
}

// WithErrors adds the scan errors to the report.
func WithErrors(errs []ScanError) WriteOption {
	return func(c *writeConfig) { c.errors = errs }
}

func writeOptions(opts []WriteOption) writeConfig {
	var cfg writeConfig
	for _, o := range opts {
		o(&cfg)
	}
	return cfg
}

// reportErrors returns errs with the paths written as the findings' paths.
func reportErrors(errs []ScanError) []ScanError {
	if len(errs) == 0 {
		return nil
	}
	cwd, _ := os.Getwd()
	out := make([]ScanError, len(errs))
	for i, e := range errs {
		out[i], _ = reportError(e, cwd)
	}
	return out
}

// reportError writes the error's path as reportPath does, also where the
// message names it, so the report doesn't carry the runner's directory.
// local reports whether the file is inside cwd.
func reportError(e ScanError, cwd string) (_ ScanError, local bool) {
	if e.File == "" {
		return e, false
	}
	file, local := reportPath(e.File, cwd)
	if file != e.File {
		e.Message = strings.ReplaceAll(e.Message, e.File, file)
		e.File = file
	}
	return e, local
}

// errorCheckName is the Code Quality check name of a scan error.
const errorCheckName = "glsec-error"

func codeClimateError(e ScanError) codeClimateIssue {
	fields, _ := json.Marshal([]any{errorCheckName, e.File, e.Message}) // strings always marshal
	h := sha256.Sum256(fields)
	path := e.File
	if path == "" {
		path = "."
	}
	return codeClimateIssue{
		Type:        "issue",
		CheckName:   errorCheckName,
		Description: "glsec could not scan this file: " + e.Message,
		Categories:  []string{"Bug Risk"},
		Severity:    "blocker",
		Fingerprint: hex.EncodeToString(h[:]),
		Location:    codeClimateLocation{Path: path, Lines: codeClimateLines{Begin: 1}},
	}
}
