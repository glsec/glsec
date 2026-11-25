// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

// checkRegistryBuildCache reports a job that writes a container build cache to
// a fixed registry reference (#1500). GitLab keeps cache: of protected and
// unprotected refs apart, but a registry cache is a plain image reference
// that every pipeline with registry access reads and writes: a branch can
// push cache entries that a protected build then reuses as layers. The caller
// skips jobs that run on protected refs only.
func checkRegistryBuildCache(name string, job *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	for _, line := range CollectJobScriptLines(job) {
		if !strings.Contains(line.Value, "cache") {
			continue
		}
		for _, cmd := range shellCommands(line.Value) {
			ref := registryCacheWrite(commandWords(cmd.text))
			if ref == "" {
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "GL046",
				Severity: finding.Warn,
				Job:      name,
				Message:  fmt.Sprintf("job writes a registry build cache (%s) that every branch shares — GitLab's protected-cache separation doesn't cover the registry, so an unprotected branch can push cache entries a protected build reuses as layers; write the cache only from protected refs, or use a per-branch cache reference", ref),
				File:     file,
				Line:     parser.ScalarContentLine(line, cmd.line),
				Col:      line.Column,
			})
		}
	}
	return findings
}

// registryCacheWrite returns the cache reference a build command writes to the
// registry, or "" when it writes none, writes a per-run reference, or only
// reads one (--cache-from). Covered: Kaniko --cache (to --cache-repo, by
// default <destination>/cache), docker buildx build / docker build with
// --cache-to type=registry, and buildctl --export-cache type=registry.
func registryCacheWrite(words []string) string {
	words = stripExecWrapper(words)
	if len(words) == 0 {
		return ""
	}
	name := commandName(words)
	var ref string
	switch {
	case name == "executor" || strings.HasSuffix(words[0], "/kaniko/executor"):
		cache, repo := false, ""
		for i := 1; i < len(words); i++ {
			switch w := words[i]; {
			case w == "--cache" || w == "--cache=true":
				cache = true
			case w == "--cache-repo" && i+1 < len(words):
				i++
				repo = words[i]
			case strings.HasPrefix(w, "--cache-repo="):
				repo = strings.TrimPrefix(w, "--cache-repo=")
			}
		}
		if !cache {
			return ""
		}
		if repo == "" {
			repo = "<destination>/cache"
		}
		ref = "kaniko --cache-repo " + repo
	case name == "docker" || name == "buildctl":
		flag := "--cache-to"
		if name == "buildctl" {
			flag = "--export-cache"
		}
		for i := 1; i < len(words); i++ {
			v := ""
			switch w := words[i]; {
			case w == flag && i+1 < len(words):
				i++
				v = words[i]
			case strings.HasPrefix(w, flag+"="):
				v = strings.TrimPrefix(w, flag+"=")
			default:
				continue
			}
			if r := registryCacheRef(strings.Trim(v, `"'`)); r != "" {
				ref = flag + " " + r
				break
			}
		}
	}
	if ref == "" {
		return ""
	}
	for _, v := range perRunTagVars {
		if strings.Contains(ref, "$"+v) || strings.Contains(ref, "${"+v+"}") {
			return ""
		}
	}
	return ref
}

// registryCacheRef returns the ref= of a type=registry cache export.
func registryCacheRef(spec string) string {
	registry, ref := false, ""
	for _, part := range strings.Split(spec, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "type":
			registry = v == "registry"
		case "ref":
			ref = v
		}
	}
	if !registry || ref == "" {
		return ""
	}
	return ref
}

// registryCacheProtectedOnly reports a job that runs on protected refs only,
// evaluated as GL013 and GL081 do (#1494): only: lists nothing but main,
// master or tags, or every rules entry that can run the job has an if: that
// restricts to the default branch, a named branch, a tag or a protected ref.
func registryCacheProtectedOnly(job *yaml.Node) bool {
	if gl046ProtectedOnly(job) {
		return true
	}
	if only := parser.FindKey(job, "only"); only != nil && only.Kind == yaml.SequenceNode && len(only.Content) > 0 {
		for _, item := range only.Content {
			switch item.Value {
			case "main", "master", "tags":
			default:
				return false
			}
		}
		return true
	}
	rules := parser.FindKey(job, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode || parser.IsReference(rules) {
		return false
	}
	running := 0
	for _, item := range rules.Content {
		if item.Kind != yaml.MappingNode || parser.IsReference(item) {
			return false
		}
		if when := parser.FindKey(item, "when"); when != nil && when.Value == "never" {
			continue
		}
		cond := parser.FindKey(item, "if")
		if cond == nil || !ifRestrictsToProtected(cond.Value) {
			return false
		}
		running++
	}
	return running > 0
}
