// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"strconv"
	"strings"
)

// Dedupe merges findings that report the same problem at the same place. YAML
// anchors make one piece of configuration part of several jobs, so a rule
// reports it once per job, at the anchor's line, with messages that differ
// only in the quoted job name. The merged finding keeps the first job and the highest
// severity any of them carries.
func Dedupe(findings []Finding) []Finding {
	type key struct {
		rule, file, message string
		line, col           int
	}
	index := map[key]int{}
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		msg := f.Message
		if f.Job != "" {
			msg = strings.ReplaceAll(msg, strconv.Quote(f.Job), "\x00")
		}
		k := key{f.RuleID, f.File, msg, f.Line, f.Col}
		i, seen := index[k]
		if !seen {
			index[k] = len(out)
			out = append(out, f)
			continue
		}
		if rank(f.Severity) > rank(out[i].Severity) {
			out[i].Severity = f.Severity
		}
	}
	return out
}

func rank(s Severity) int {
	switch s {
	case Error:
		return 2
	case Warn:
		return 1
	}
	return 0
}
