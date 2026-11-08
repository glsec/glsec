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

type gl089 struct{}

var GL089 = &gl089{}

func (r *gl089) ID() string { return "GL089" }

// renovateCmdRe finds the Renovate CLI in command position: at the start of a
// command, after npx/bunx/pnpm dlx/exec, behind a path, and after leading
// VAR=value assignments. renovate-config-validator and "npm install renovate"
// don't match.
var renovateCmdRe = mustCompilePrefiltered(
	`(?:^|[;&|(]|\$\()\s*(?:\w+=\S*\s+)*` +
		`(?:(?:npx|bunx)\s+(?:-y\s+|--yes\s+)?|pnpm\s+dlx\s+|exec\s+)?` +
		`(?:[\w./-]*/)?renovate(?:\s|$)`)

var (
	autodiscoverOnRe  = regexp.MustCompile(`(?:^|\s)--autodiscover(?:=true)?(?:\s|$)`)
	autodiscoverOffRe = regexp.MustCompile(`(?:^|\s)--autodiscover=false(?:\s|$)`)
	// autodiscoverLimitRe matches the flags that limit which repositories
	// autodiscovery takes: by path, GitLab namespace, topic or Bitbucket project.
	autodiscoverLimitRe = regexp.MustCompile(`(?:^|\s)--autodiscover-(?:filter|namespaces|topics|projects)\b`)
)

// autodiscoverLimitVars are the environment forms of autodiscoverLimitRe.
var autodiscoverLimitVars = []string{
	"RENOVATE_AUTODISCOVER_FILTER",
	"RENOVATE_AUTODISCOVER_NAMESPACES",
	"RENOVATE_AUTODISCOVER_TOPICS",
	"RENOVATE_AUTODISCOVER_PROJECTS",
}

// Check reports a job that runs Renovate with autodiscovery and nothing that
// limits it: the bot then works on every project its token can reach (#677).
// Hidden jobs don't run; a job that extends one gets its script from it.
func (r *gl089) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	in := NewInheritance(doc)
	// Whether an item runs renovate at all, cached for items shared through
	// an anchor (#766); the rest depends on the job's variables.
	runsRenovate := nodeMemo[bool]{}
	// Collected once: walking every job for them per job was quadratic (#838).
	pipelineVars := pipelineVariablesOf(doc)
	parser.EachJob(doc, func(name, job *yaml.Node) {
		if strings.HasPrefix(name.Value, ".") {
			return
		}
		var vars jobVariables
		varsDone := false
		for _, key := range []string{"before_script", "script"} {
			block := in.Key(job, key)
			if !isScriptList(block) {
				continue
			}
			for _, item := range block.Content {
				if item.Kind != yaml.ScalarNode || !runsRenovate.get(item, func() bool { return renovateCmdRe.MatchString(unwrappedLine(item.Value)) }) {
					continue
				}
				if !varsDone {
					vars, varsDone = variablesOf(in, job, pipelineVars), true
				}
				for _, line := range strings.Split(unwrappedLine(strings.ReplaceAll(item.Value, "\\\n", " ")), "\n") {
					if !unlimitedAutodiscover(line, vars) {
						continue
					}
					findings = append(findings, finding.Finding{
						RuleID:   "GL089",
						Severity: finding.Warn,
						Job:      name.Value,
						Message:  fmt.Sprintf("job %q runs Renovate with autodiscovery and no filter — the bot works on every project its token can reach; set RENOVATE_AUTODISCOVER_FILTER (or autodiscoverNamespaces/autodiscoverTopics), unless a config file in the repository already does", name.Value),
						File:     file,
						Line:     item.Line,
						Col:      item.Column,
					})
					return
				}
			}
		}
	})
	return findings
}

// unlimitedAutodiscover reports whether line runs Renovate with autodiscovery
// switched on, by flag or variable, and neither a flag nor a variable limits
// it. A flag on the command line wins over the variable, as in Renovate.
func unlimitedAutodiscover(line string, vars jobVariables) bool {
	m := renovateCmdRe.FindStringIndex(line)
	if m == nil {
		return false
	}
	args := line[m[1]:]
	if end := strings.IndexAny(args, "|;&"); end >= 0 {
		args = args[:end]
	}
	on := autodiscoverOnRe.MatchString(args) ||
		!autodiscoverOffRe.MatchString(args) && vars.sometimes("RENOVATE_AUTODISCOVER", isTrueValue)
	if !on || autodiscoverLimitRe.MatchString(args) {
		return false
	}
	for _, name := range autodiscoverLimitVars {
		if vars.always(name, isSetValue) {
			return false
		}
	}
	return true
}
