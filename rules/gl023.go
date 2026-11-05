// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"regexp"
	"strings"

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
	// byCommand checks each shell command on its own instead of the whole
	// script item, so a comment or another command's flag doesn't count.
	byCommand bool
	// frozenVars make the manager refuse to change the lockfile when set in a
	// variables: block to a value frozenValue accepts.
	frozenVars  []string
	frozenValue func(string) bool
	// frozenBy matches a script line that does the same for later commands.
	frozenBy *regexp.Regexp
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
		manager:     "bundler",
		trigger:     regexp.MustCompile(`\bbundle\s+install\b`),
		strictFlag:  regexp.MustCompile(`--frozen\b|--deployment\b`),
		skip:        nil,
		hint:        "bundle install --frozen",
		frozenVars:  []string{"BUNDLE_FROZEN", "BUNDLE_DEPLOYMENT"},
		frozenValue: func(v string) bool { return v == "true" || v == "1" },
		// bundle config set --global frozen 'true'.
		frozenBy: regexp.MustCompile(`\bbundle\s+config\s+(?:set\s+)?(?:--(?:global|local)\s+)?(?:frozen|deployment)\s+["']?(?:true|1)\b`),
	},
	{
		// uv re-locks before syncing unless --locked or --frozen is given.
		// --check and --dry-run change nothing.
		manager:     "uv",
		trigger:     regexp.MustCompile(`\buv\s+sync(?:\s|$|["';)])`),
		strictFlag:  regexp.MustCompile(`--locked\b|--frozen\b`),
		skip:        regexp.MustCompile(`\s--(?:check|dry-run)\b`),
		hint:        "uv sync --locked",
		byCommand:   true,
		frozenVars:  []string{"UV_LOCKED", "UV_FROZEN"},
		frozenValue: uvBoolTrue,
		// uv's docs call uv lock --check the equivalent of --locked.
		frozenBy: regexp.MustCompile(`\buv\s+lock\b[^\n;&|]*\s--(?:check|locked)\b|\bUV_(?:LOCKED|FROZEN)\s*=\s*["']?(?i:y|yes|t|true|on|1)\b`),
	},
	{
		// A package argument doesn't match: adding a package is GL022's. Bun
		// doesn't freeze the lockfile in CI by itself; --production implies it.
		manager:    "Bun",
		trigger:    regexp.MustCompile(`(?m)\bbun\s+(?:install|i)(?:\s+--?[\w=@./:-]+)*\s*(?:$|[|&;"')])`),
		strictFlag: regexp.MustCompile(`--frozen-lockfile\b|--production\b`),
		skip:       regexp.MustCompile(`\s(?:-g|--global)\b`),
		hint:       "bun ci",
		byCommand:  true,
	},
}

// uvBoolTrue reports a value uv reads as true in a boolean variable.
func uvBoolTrue(v string) bool {
	switch strings.ToLower(v) {
	case "y", "yes", "t", "true", "on", "1":
		return true
	}
	return false
}

func (r *gl023) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	in := NewInheritance(doc)
	globalFrozen := frozenManagers(parser.FindKey(parser.Unwrap(doc), "variables"))

	// What each line says on its own, cached for lines shared through an
	// anchor (#766).
	type lineFacts struct {
		sets uint // managers the line freezes for later commands
		hits []lockfileHit
	}
	facts := nodeMemo[lineFacts]{}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		lines := CollectJobScriptLines(job)
		// GitLab merges a job's variables: with those inherited through
		// extends:, so a job's own variables: block (for an unrelated key) does
		// not drop an inherited BUNDLE_FROZEN. Check every block in the chain,
		// not just the nearest one (#1102).
		frozen := globalFrozen
		for _, vars := range in.Chain(job, "variables") {
			frozen |= frozenManagers(vars)
		}
		for _, l := range lines {
			lf := facts.get(l, func() lineFacts {
				return lineFacts{sets: frozenByLine(l.Value), hits: lockfileHits(l, file)}
			})
			frozen |= lf.sets
			for _, hit := range lf.hits {
				if frozen&hit.manager != 0 {
					continue
				}
				f := hit.finding
				f.Job = name.Value
				findings = append(findings, f)
				break // one finding per script item
			}
		}
	})

	return findings
}

// frozenManagers returns a bit for each lockfileChecks entry a variables:
// block freezes.
func frozenManagers(vars *yaml.Node) uint {
	if vars == nil || vars.Kind != yaml.MappingNode {
		return 0
	}
	var frozen uint
	for i, lc := range lockfileChecks {
		for _, k := range lc.frozenVars {
			v := parser.FindKey(vars, k)
			if v != nil && v.Kind == yaml.MappingNode {
				v = parser.FindKey(v, "value")
			}
			if v != nil && v.Kind == yaml.ScalarNode && lc.frozenValue(v.Value) {
				frozen |= 1 << i
			}
		}
	}
	return frozen
}

// frozenByLine returns a bit for each lockfileChecks entry a script line
// freezes for the commands after it.
func frozenByLine(line string) uint {
	var frozen uint
	for i, lc := range lockfileChecks {
		if lc.frozenBy != nil && lc.frozenBy.MatchString(line) {
			frozen |= 1 << i
		}
	}
	return frozen
}

// lockfileHit is a finding for the lockfileChecks entry in the manager bit.
type lockfileHit struct {
	manager uint
	finding finding.Finding
}

// lockfileHits returns at most one finding per manager for a script item.
func lockfileHits(l *yaml.Node, file string) []lockfileHit {
	var hits []lockfileHit
	for i, lc := range lockfileChecks {
		// The trigger on the whole item keeps shellCommands off the many
		// lines that don't name the manager.
		if !lc.trigger.MatchString(l.Value) {
			continue
		}
		line, ok := l.Line, false
		if lc.byCommand {
			for _, c := range shellCommands(l.Value) {
				if lc.unlocked(c.text) {
					line, ok = parser.ScalarContentLine(l, c.line), true
					break
				}
			}
		} else {
			ok = lc.unlocked(l.Value)
		}
		if !ok {
			continue
		}
		hits = append(hits, lockfileHit{manager: 1 << i, finding: finding.Finding{
			RuleID:   "GL023",
			Severity: finding.Warn,
			Message:  fmt.Sprintf("%s install without lockfile enforcement — use %q to guarantee reproducible dependency resolution", lc.manager, lc.hint),
			File:     file,
			Line:     line,
			Col:      l.Column,
		}})
	}
	return hits
}

// unlocked reports whether text runs the install without enforcing the
// lockfile.
func (lc *lockfileCheck) unlocked(text string) bool {
	return lc.trigger.MatchString(text) &&
		(lc.skip == nil || !lc.skip.MatchString(text)) &&
		(lc.strictFlag == nil || !lc.strictFlag.MatchString(text))
}
