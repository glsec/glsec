package rules

import (
	"fmt"
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl022 struct{}

var GL022 = &gl022{}

func (r *gl022) ID() string { return "GL022" }

// pmInstallCheck describes how to detect an unpinned package manager install.
type pmInstallCheck struct {
	manager string
	trigger *regexp.Regexp // matches the install command
	pinned  *regexp.Regexp // if present, version is pinned → no finding
	skip    *regexp.Regexp // if present, skip the line entirely (e.g. -r file)
}

// pmUpdateCheck describes explicit update-to-latest commands that are always wrong in CI.
type pmUpdateCheck struct {
	manager string
	re      *regexp.Regexp
}

var (
	pmInstallChecks = []pmInstallCheck{
		{
			manager: "pip",
			trigger: regexp.MustCompile(`\bpip[23]?\s+install\b`),
			pinned:  regexp.MustCompile(`==|~=|!=|>=|<=`),
			skip:    regexp.MustCompile(`\s-r\s|\s-r$|-e\s|\.\s*(?:$|&&|\|)|--upgrade\b|-U\b`),
		},
		{
			manager: "npm (global)",
			trigger: regexp.MustCompile(`\bnpm\s+install\b.*(?:-g\b|--global\b)`),
			pinned:  regexp.MustCompile(`@\d`),
			skip:    nil,
		},
		{
			manager: "apt-get",
			trigger: regexp.MustCompile(`\bapt(?:-get)?\s+install\b`),
			pinned:  regexp.MustCompile(`\b\S+=\d`),
			skip:    nil,
		},
		{
			manager: "apk",
			trigger: regexp.MustCompile(`\bapk\s+add\b`),
			pinned:  regexp.MustCompile(`\b\S+=\d`),
			skip:    nil,
		},
		{
			manager: "gem",
			trigger: regexp.MustCompile(`\bgem\s+install\b`),
			pinned:  regexp.MustCompile(`(?:-v|--version)\s+\d`),
			skip:    nil,
		},
		{
			manager: "cargo",
			trigger: regexp.MustCompile(`\bcargo\s+install\b`),
			pinned:  regexp.MustCompile(`(?:--version|--vers)\s+\d`),
			skip:    nil,
		},
	}

	pmUpdateChecks = []pmUpdateCheck{
		{"npm", regexp.MustCompile(`\bnpm\s+update\b`)},
		{"yarn", regexp.MustCompile(`\byarn\s+upgrade\b`)},
		{"pnpm", regexp.MustCompile(`\bpnpm\s+update\b`)},
		{"composer", regexp.MustCompile(`\bcomposer\s+update\b`)},
		{"bundler", regexp.MustCompile(`\bbundle\s+update\b`)},
		{"gem", regexp.MustCompile(`\bgem\s+update\b`)},
		{"cargo", regexp.MustCompile(`\bcargo\s+update\b`)},
		{"pip (--upgrade)", regexp.MustCompile(`\bpip[23]?\s+install\b.*(?:--upgrade\b|-U\b)`)},
	}
)

func (r *gl022) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		lines := collectScriptLines(job)
		for _, l := range lines {
			if f := checkPMLine(l.Value, file, l.Line, l.Column); f != nil {
				f.Job = name.Value
				findings = append(findings, *f)
			}
		}
	})

	return findings
}

func checkPMLine(line, file string, lineNum, col int) *finding.Finding {
	// Explicit update commands — always wrong in CI.
	for _, uc := range pmUpdateChecks {
		if uc.re.MatchString(line) {
			f := finding.Finding{
				RuleID:   "GL022",
				Severity: finding.Warn,
				Message:  fmt.Sprintf("%s update command used in CI — always pulls latest, making the pipeline non-reproducible", uc.manager),
				File:     file,
				Line:     lineNum,
				Col:      col,
			}
			return &f
		}
	}

	// Install without version pin.
	for _, ic := range pmInstallChecks {
		if !ic.trigger.MatchString(line) {
			continue
		}
		if ic.skip != nil && ic.skip.MatchString(line) {
			continue
		}
		if ic.pinned != nil && ic.pinned.MatchString(line) {
			continue
		}
		f := finding.Finding{
			RuleID:   "GL022",
			Severity: finding.Warn,
			Message:  fmt.Sprintf("%s install without version pin — use an exact version to make the pipeline reproducible", ic.manager),
			File:     file,
			Line:     lineNum,
			Col:      col,
		}
		return &f
	}

	return nil
}
