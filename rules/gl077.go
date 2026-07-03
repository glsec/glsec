package rules

import (
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl077 struct{}

var GL077 = &gl077{}

func (r *gl077) ID() string { return "GL077" }

// ipcHostRe matches --ipc host / --ipc=host.
var ipcHostRe = regexp.MustCompile(`--ipc[=\s]+host(?:\s|$)`)

func (r *gl077) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		v := line.Value
		if strings.HasPrefix(strings.TrimSpace(v), "#") {
			return
		}
		if !dockerRunRe.MatchString(v) || !ipcHostRe.MatchString(v) {
			return
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL077",
			Severity: finding.Warn,
			Job:      job,
			Message:  "docker run --ipc host shares the host IPC namespace — the container can read the host's shared memory and POSIX message queues and signal host processes; omit --ipc or scope it with --ipc container:<id>",
			File:     file,
			Line:     line.Line,
			Col:      line.Column,
		})
	})
	return findings
}
