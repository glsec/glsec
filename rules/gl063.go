package rules

import (
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl063 struct{}

var GL063 = &gl063{}

func (r *gl063) ID() string { return "GL063" }

var (
	// chmodModeRe captures the mode argument of a chmod invocation: any
	// leading flags (-R, -v, …) followed by the first non-flag token.
	chmodModeRe = regexp.MustCompile(`\bchmod\s+((?:-[A-Za-z-]+\s+)*)(\S+)`)
	octalModeRe = regexp.MustCompile(`^[0-7]{3,4}$`)
	// symbolicWorldWriteRe matches a symbolic clause granting write to
	// "others" or "all" (who part contains o or a, op is + or =, perms have w).
	symbolicWorldWriteRe = regexp.MustCompile(`[ugoa]*[ao][ugoa]*[+=][rwxXst]*w`)
)

func (r *gl063) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		v := line.Value
		if strings.HasPrefix(strings.TrimSpace(v), "#") {
			return
		}
		for _, m := range chmodModeRe.FindAllStringSubmatch(v, -1) {
			if !worldWritableMode(m[2]) {
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "GL063",
				Severity: finding.Warn,
				Job:      job,
				Message:  "chmod grants world-writable permissions — on shared runners other processes can modify the file, risking a TOCTOU race if it is later executed; use the minimal permission (e.g. chmod +x) instead",
				File:     file,
				Line:     line.Line,
				Col:      line.Column,
			})
		}
	})
	return findings
}

// worldWritableMode reports whether a chmod mode token grants write to others.
func worldWritableMode(mode string) bool {
	if octalModeRe.MatchString(mode) {
		last := mode[len(mode)-1] - '0'
		return last&2 != 0
	}
	return symbolicWorldWriteRe.MatchString(mode)
}
