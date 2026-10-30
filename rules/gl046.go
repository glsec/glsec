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

type gl046 struct{}

var GL046 = &gl046{}

func (r *gl046) ID() string { return "GL046" }

// cacheKeyVars extends the GL002 user-controlled variable set with CI_COMMIT_REF_SLUG,
// which is a normalised form of CI_COMMIT_REF_NAME and carries the same cache-poisoning risk.
var cacheKeyVars = append(append([]string{}, userControlledVars...), "CI_COMMIT_REF_SLUG")

var cacheKeyVarRe = regexp.MustCompile(
	`\$\{?(` + strings.Join(cacheKeyVars, "|") + `)\b`,
)

func (r *gl046) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	if def := parser.FindKey(mapping, "default"); def != nil {
		findings = append(findings, checkCacheNode(parser.FindKey(def, "cache"), file, "")...)
		findings = append(findings, checkCacheUnprotect(parser.FindKey(def, "cache"), file, "", finding.Warn)...)
	}

	in := NewInheritance(doc)
	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if !in.Has(job, "cache") {
			return
		}
		job = in.Effective(job)
		// Without unprotect: true GitLab keeps the caches of protected and
		// unprotected refs apart, so a key a branch name can steer can't
		// reach a job that only runs on protected refs (#1003).
		cache := parser.FindKey(job, "cache")
		if !gl046ProtectedOnly(job) || cacheUnprotected(cache) {
			for _, f := range checkCacheNode(cache, file, "") {
				f.Job = name.Value
				findings = append(findings, f)
			}
		}
		// A hidden job is a template: the job that extends it decides where it
		// runs. A job that only runs on protected refs writes the shared cache
		// from the trusted side, the documented use of unprotect:.
		if strings.HasPrefix(name.Value, ".") || gl046ProtectedOnly(job) {
			return
		}
		// A deploy job restores the shared cache on a protected branch; an MR job
		// is the side an outsider controls.
		severity := finding.Warn
		if IsDeployLikeJob(name.Value, job) || jobHasMRTrigger(job) {
			severity = finding.Error
		}
		findings = append(findings, checkCacheUnprotect(parser.FindKey(job, "cache"), file, name.Value, severity)...)
	})

	return findings
}

// checkCacheUnprotect flags cache entries that set unprotect: true and can
// write the cache. Unprotected caches share their keys with protected
// branches, so a job on any branch can fill the cache a protected job restores.
// policy: pull only reads; a policy taken from a variable cannot be resolved
// and is treated as writing.
func checkCacheUnprotect(node *yaml.Node, file, job string, severity finding.Severity) []finding.Finding {
	var findings []finding.Finding
	for _, entry := range cacheEntries(node) {
		unprotect := parser.FindKey(entry, "unprotect")
		if unprotect == nil || unprotect.Value != "true" {
			continue
		}
		if policy := parser.FindKey(entry, "policy"); policy != nil && policy.Value == "pull" {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL046",
			Severity: severity,
			Job:      job,
			Message:  "cache: unprotect: true shares this cache with unprotected branches and the job can write it — anyone who can push a branch can poison the cache a protected pipeline restores; drop unprotect: or set policy: pull",
			File:     file,
			Line:     unprotect.Line,
			Col:      unprotect.Column,
		})
	}
	return findings
}

func checkCacheNode(node *yaml.Node, file, job string) []finding.Finding {
	var findings []finding.Finding
	for _, entry := range cacheEntries(node) {
		findings = append(findings, checkCacheMapping(entry, file, job)...)
	}
	return findings
}

// cacheEntries returns the cache mappings of a cache: value, a single mapping
// or a list.
func cacheEntries(node *yaml.Node) []*yaml.Node {
	if node == nil {
		return nil
	}
	items := []*yaml.Node{node}
	if node.Kind == yaml.SequenceNode {
		items = node.Content
	}
	var entries []*yaml.Node
	for _, item := range items {
		if item.Kind == yaml.MappingNode {
			entries = append(entries, item)
		}
	}
	return entries
}

func checkCacheMapping(node *yaml.Node, file, job string) []finding.Finding {
	keyNode := parser.FindKey(node, "key")
	if keyNode == nil {
		return nil
	}

	switch keyNode.Kind {
	case yaml.ScalarNode:
		if m := cacheKeyVarRe.FindStringSubmatch(keyNode.Value); m != nil {
			return []finding.Finding{{
				RuleID:   "GL046",
				Severity: finding.Warn,
				Job:      job,
				Message: fmt.Sprintf(
					"cache key contains user-controlled variable $%s — an attacker can craft a branch name to collide with the cache key of a protected pipeline and inject malicious build artefacts",
					m[1],
				),
				File: file,
				Line: keyNode.Line,
				Col:  keyNode.Column,
			}}
		}
	case yaml.MappingNode:
		prefixNode := parser.FindKey(keyNode, "prefix")
		if prefixNode != nil && prefixNode.Kind == yaml.ScalarNode {
			if m := cacheKeyVarRe.FindStringSubmatch(prefixNode.Value); m != nil {
				return []finding.Finding{{
					RuleID:   "GL046",
					Severity: finding.Warn,
					Job:      job,
					Message: fmt.Sprintf(
						"cache key prefix contains user-controlled variable $%s — an attacker can craft a branch name to collide with the cache key of a protected pipeline and inject malicious build artefacts",
						m[1],
					),
					File: file,
					Line: prefixNode.Line,
					Col:  prefixNode.Column,
				}}
			}
		}
	}
	return nil
}

// protectedRefCondRe matches a rules:if clause that holds only on the default
// branch or on protected refs.
var protectedRefCondRe = regexp.MustCompile(
	`\$\{?CI_COMMIT_BRANCH\}?\s*==\s*\$\{?CI_DEFAULT_BRANCH\b` +
		`|\$\{?CI_DEFAULT_BRANCH\}?\s*==\s*\$\{?CI_COMMIT_BRANCH\b` +
		`|\$\{?CI_COMMIT_REF_NAME\}?\s*==\s*\$\{?CI_DEFAULT_BRANCH\b` +
		`|\$\{?CI_DEFAULT_BRANCH\}?\s*==\s*\$\{?CI_COMMIT_REF_NAME\b` +
		`|\$\{?CI_COMMIT_(?:BRANCH|REF_NAME)\}?\s*==\s*["'](?:main|master)["']` +
		`|\$\{?CI_COMMIT_REF_PROTECTED\}?\s*==\s*["']?true\b`,
)

// gl046ProtectedOnly reports whether a job runs only on the default branch or
// on protected refs: every rules entry that can run the job has an if: whose
// every || branch requires such a ref, or only: lists nothing but main/master.
func gl046ProtectedOnly(job *yaml.Node) bool {
	if only := parser.FindKey(job, "only"); only != nil {
		if only.Kind != yaml.SequenceNode || len(only.Content) == 0 {
			return false
		}
		for _, item := range only.Content {
			if item.Value != "main" && item.Value != "master" {
				return false
			}
		}
		return true
	}
	rules := parser.FindKey(job, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return false
	}
	running := 0
	for _, item := range rules.Content {
		if item.Kind != yaml.MappingNode {
			return false
		}
		if when := parser.FindKey(item, "when"); when != nil && when.Value == "never" {
			continue
		}
		cond := parser.FindKey(item, "if")
		if cond == nil {
			return false
		}
		for _, branch := range strings.Split(cond.Value, "||") {
			if !protectedRefCondRe.MatchString(branch) {
				return false
			}
		}
		running++
	}
	return running > 0
}

// cacheUnprotected reports whether any entry of a cache: sets unprotect: true.
func cacheUnprotected(node *yaml.Node) bool {
	for _, entry := range cacheEntries(node) {
		if u := parser.FindKey(entry, "unprotect"); u != nil && u.Value == "true" {
			return true
		}
	}
	return false
}
