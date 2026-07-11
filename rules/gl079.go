package rules

import (
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl079 struct{}

var GL079 = &gl079{}

func (r *gl079) ID() string { return "GL079" }

var (
	// pipInstallRe matches a pip install invocation (pip, pip3, pip2, or
	// `python -m pip install`).
	pipInstallRe = regexp.MustCompile(`\bpip[0-9]*\s+install\b`)
	// extraIndexRe matches pip's --extra-index-url flag, which adds a package
	// index in addition to the default one.
	extraIndexRe = regexp.MustCompile(`--extra-index-url(?:[=\s]|$)`)
)

func (r *gl079) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		v := line.Value
		if strings.HasPrefix(strings.TrimSpace(v), "#") {
			return
		}
		if !pipInstallRe.MatchString(v) || !extraIndexRe.MatchString(v) {
			return
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL079",
			Severity: finding.Warn,
			Job:      job,
			Message:  "pip install with --extra-index-url adds a package index alongside the default — pip resolves the highest version across all indexes, so an attacker who publishes a higher-versioned package of the same name on the public index gets it pulled into the build (dependency confusion); use a single trusted --index-url plus hash-pinned requirements or a lockfile instead",
			File:     file,
			Line:     line.Line,
			Col:      line.Column,
		})
	})
	return findings
}
