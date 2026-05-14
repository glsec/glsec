package rules

import (
	"fmt"
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl023 struct{}

var GL023 = &gl023{}

func (r *gl023) ID() string { return "GL023" }

// lockfileCheck describes a non-lockfile-strict install command.
type lockfileCheck struct {
	manager    string
	trigger    *regexp.Regexp // matches the non-strict command
	strictFlag *regexp.Regexp // if present in the same line, command is already strict
	skip       *regexp.Regexp // skip the line entirely (e.g., package argument present)
	hint       string         // safe alternative to show in the message
}

var lockfileChecks = []lockfileCheck{
	{
		// npm install (bare, no package args) — strict form is `npm ci`
		manager: "npm",
		// Matches npm install followed by only flags (words starting with -), then end/separator.
		// If a non-flag argument (package name) follows, the regex won't match.
		trigger:    regexp.MustCompile(`\bnpm\s+install(?:\s+--?[\w=@./:-]+)*\s*(?:$|[|&;])`),
		strictFlag: nil, // npm ci is a different command entirely
		skip:       regexp.MustCompile(`-g\b|--global\b`),
		hint:       "npm ci",
	},
	{
		manager:    "yarn",
		trigger:    regexp.MustCompile(`\byarn\s+install\b`),
		strictFlag: regexp.MustCompile(`--frozen-lockfile\b|--immutable\b`),
		skip:       nil,
		hint:       "yarn install --frozen-lockfile",
	},
	{
		manager:    "pnpm",
		trigger:    regexp.MustCompile(`\bpnpm\s+install\b`),
		strictFlag: regexp.MustCompile(`--frozen-lockfile\b`),
		skip:       nil,
		hint:       "pnpm install --frozen-lockfile",
	},
	{
		manager:    "bundler",
		trigger:    regexp.MustCompile(`\bbundle\s+install\b`),
		strictFlag: regexp.MustCompile(`--frozen\b|--deployment\b`),
		skip:       nil,
		hint:       "bundle install --frozen",
	},
}

func (r *gl023) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(_ *yaml.Node, job *yaml.Node) {
		lines := collectScriptLines(job)
		for _, l := range lines {
			if f := checkLockfileLine(l.Value, file, l.Line, l.Column); f != nil {
				findings = append(findings, *f)
			}
		}
	})

	return findings
}

func checkLockfileLine(line, file string, lineNum, col int) *finding.Finding {
	for _, lc := range lockfileChecks {
		if !lc.trigger.MatchString(line) {
			continue
		}
		if lc.skip != nil && lc.skip.MatchString(line) {
			continue
		}
		if lc.strictFlag != nil && lc.strictFlag.MatchString(line) {
			continue
		}
		f := finding.Finding{
			RuleID:   "GL023",
			Severity: finding.Warn,
			Message:  fmt.Sprintf("%s install without lockfile enforcement — use %q to guarantee reproducible dependency resolution", lc.manager, lc.hint),
			File:     file,
			Line:     lineNum,
			Col:      col,
		}
		return &f
	}
	return nil
}
