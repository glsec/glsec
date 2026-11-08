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
	index := map[dedupeKey]int{}
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		k := keyOf(f)
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

// DedupeSuppressed is Dedupe for suppressed findings. One suppression covers
// the line, so the first finding's source and reason stand for all of them.
func DedupeSuppressed(suppressed []Suppressed) []Suppressed {
	index := map[dedupeKey]int{}
	out := make([]Suppressed, 0, len(suppressed))
	for _, s := range suppressed {
		k := keyOf(s.Finding)
		i, seen := index[k]
		if !seen {
			index[k] = len(out)
			out = append(out, s)
			continue
		}
		if rank(s.Severity) > rank(out[i].Severity) {
			out[i].Severity = s.Severity
		}
	}
	return out
}

// DedupeMoved merges findings moved to a job (see Finding.Origin) that report
// the same configuration: with each other, so a template many jobs use counts
// once as it does in its own file, and with what that file reports itself.
// note is the suffix the move added to a message.
func DedupeMoved(findings []Finding, note func(Origin) string) []Finding {
	type place struct {
		rule, file, message string
		line                int
	}
	seen := map[place]bool{}
	for _, f := range findings {
		if f.Origin == (Origin{}) {
			k := keyOf(f)
			seen[place{k.rule, k.file, k.message, k.line}] = true
		}
	}
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if f.Origin != (Origin{}) {
			orig := f
			orig.Message = strings.TrimSuffix(f.Message, note(f.Origin))
			k := keyOf(orig)
			p := place{k.rule, f.Origin.File, k.message, f.Origin.Line}
			if seen[p] {
				continue
			}
			seen[p] = true
		}
		out = append(out, f)
	}
	return out
}

type dedupeKey struct {
	rule, file, message string
	line, col           int
}

func keyOf(f Finding) dedupeKey {
	msg := f.Message
	if f.Job != "" {
		msg = strings.ReplaceAll(msg, strconv.Quote(f.Job), "\x00")
	}
	return dedupeKey{f.RuleID, f.File, msg, f.Line, f.Col}
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
