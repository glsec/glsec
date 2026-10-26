// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

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
	// pnpm is not listed: it turns on --frozen-lockfile by itself when CI is
	// set, and GitLab sets CI=true in every job.
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

	in := NewInheritance(doc)
	globalFrozen := bundlerFrozenVars(parser.FindKey(parser.Unwrap(doc), "variables"))

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		lines := CollectJobScriptLines(job)
		frozen := globalFrozen || bundlerFrozenVars(in.Key(job, "variables"))
		for _, l := range lines {
			if bundleConfigFrozenRe.MatchString(l.Value) {
				frozen = true
			}
			if frozen && bundleInstallRe.MatchString(l.Value) {
				continue
			}
			if f := checkLockfileLine(l.Value, file, l.Line, l.Column); f != nil {
				f.Job = name.Value
				findings = append(findings, *f)
			}
		}
	})

	return findings
}

var (
	bundleInstallRe = regexp.MustCompile(`\bbundle\s+install\b`)
	// bundleConfigFrozenRe matches bundler being set to frozen or deployment
	// mode before the install: bundle config set --global frozen 'true'.
	bundleConfigFrozenRe = regexp.MustCompile(`\bbundle\s+config\s+(?:set\s+)?(?:--(?:global|local)\s+)?(?:frozen|deployment)\s+["']?(?:true|1)\b`)
)

// bundlerFrozenVars reports whether a variables: block sets BUNDLE_FROZEN or
// BUNDLE_DEPLOYMENT, which make bundle install refuse to change the lockfile.
func bundlerFrozenVars(vars *yaml.Node) bool {
	if vars == nil || vars.Kind != yaml.MappingNode {
		return false
	}
	for _, k := range []string{"BUNDLE_FROZEN", "BUNDLE_DEPLOYMENT"} {
		v := parser.FindKey(vars, k)
		if v != nil && v.Kind == yaml.MappingNode {
			v = parser.FindKey(v, "value")
		}
		if v != nil && v.Kind == yaml.ScalarNode && (v.Value == "true" || v.Value == "1") {
			return true
		}
	}
	return false
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
