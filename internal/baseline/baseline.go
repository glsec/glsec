// Package baseline compares scan findings against an accepted set so that only
// newly introduced findings are reported. The accepted set is loaded from
// either a glsec JSON snapshot (the output of --format json) or a .glsec-ignore
// file. Matching uses a line-insensitive fingerprint so that unrelated line
// shifts in the pipeline do not resurface already-accepted findings.
package baseline

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"

	"github.com/glsec/glsec/internal/finding"
)

// Baseline is a multiset of accepted findings. Matching by count (not set
// membership) keeps duplicate findings distinct: a baseline with two accepted
// occurrences of the same fingerprint absorbs exactly two current findings, so
// a genuine third occurrence is still reported as new.
type Baseline struct {
	counts map[string]int
	// useMessage selects the fingerprint granularity. JSON snapshots carry the
	// finding message, so they match on rule+file+message. The .glsec-ignore
	// format has no message, so it can only match on rule+file.
	useMessage bool
}

type snapshot struct {
	Findings []struct {
		Rule    string `json:"rule"`
		File    string `json:"file"`
		Message string `json:"message"`
	} `json:"findings"`
}

// Empty returns a baseline with no accepted findings; every finding compared
// against it is reported as new.
func Empty() *Baseline {
	return &Baseline{counts: map[string]int{}}
}

// Load reads a baseline file, auto-detecting the format from its first
// non-blank byte: a leading '{' selects the JSON snapshot format
// (fingerprint: rule+file+message), anything else is parsed as a .glsec-ignore
// file (fingerprint: rule+file).
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(strings.TrimSpace(string(data)), "{") {
		return loadJSON(data)
	}
	return loadIgnore(data), nil
}

func loadJSON(data []byte) (*Baseline, error) {
	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, err
	}
	b := &Baseline{counts: make(map[string]int), useMessage: true}
	for _, f := range snap.Findings {
		b.counts[key(f.Rule, f.File, f.Message)]++
	}
	return b, nil
}

func loadIgnore(data []byte) *Baseline {
	b := &Baseline{counts: make(map[string]int)}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// format: <file>:<line> <ruleID>
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		loc, rule := parts[0], strings.TrimSpace(parts[1])
		colon := strings.LastIndex(loc, ":")
		if colon < 0 {
			continue
		}
		b.counts[key(rule, loc[:colon], "")]++
	}
	return b
}

func key(rule, file, message string) string {
	return rule + "\x00" + file + "\x00" + message
}

// IsNew reports whether f is absent from the baseline. When f matches a baseline
// entry, one occurrence is consumed so that callers iterating over the current
// findings account for duplicates by count.
func (b *Baseline) IsNew(f finding.Finding) bool {
	msg := ""
	if b.useMessage {
		msg = f.Message
	}
	k := key(f.RuleID, f.File, msg)
	if b.counts[k] > 0 {
		b.counts[k]--
		return false
	}
	return true
}
