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
func checkRegistryBuildCache(name string, job, globalVars *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	// Variables the cache reference may go through: the file's and the job's
	// variables:, then shell assignments earlier in the script. Built on the
	// first cache write only.
	var vars map[string]string
	var assigned [][2]string
	resolve := func(s string) string {
		if !strings.Contains(s, "$") {
			return s
		}
		if vars == nil {
			vars = literalVariables(globalVars)
			for k, v := range literalVariables(parser.FindKey(job, "variables")) {
				vars[k] = v
			}
		}
		for _, a := range assigned {
			vars[a[0]] = a[1]
		}
		assigned = assigned[:0]
		return expandVars(s, vars, "", 0)
	}
	for _, line := range CollectJobScriptLines(job) {
		hasCache := strings.Contains(line.Value, "cache")
		if !hasCache && !strings.Contains(line.Value, "=") {
			continue
		}
		for _, cmd := range shellCommands(line.Value) {
			if m := shellAssignRe.FindStringSubmatch(cmd.text); m != nil {
				assigned = append(assigned, [2]string{m[1], strings.Trim(strings.TrimSpace(m[2]), `"'`)})
				continue
			}
			if !hasCache {
				continue
			}
			ref := registryCacheWrite(commandWords(cmd.text), resolve)
			if ref == "" {
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "GL046",
				Severity: finding.Warn,
				Job:      name,
				Message:  fmt.Sprintf("job writes a registry build cache (%s) that every branch shares — GitLab's protected-cache separation doesn't cover the registry, so a pipeline changed on an unprotected branch can upload layers under the cache keys a protected build looks up; write the cache only from protected refs or use a per-branch cache reference, and cover the cache tags with protected container tags", ref),
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
// default the first --destination's repository plus /cache), docker buildx
// build / docker build with --cache-to type=registry, and buildctl
// --export-cache type=registry. resolve expands variables in a reference.
func registryCacheWrite(words []string, resolve func(string) string) string {
	words = stripExecWrapper(words)
	if len(words) == 0 {
		return ""
	}
	name := commandName(words)
	var ref string
	switch {
	case name == "executor" || strings.HasSuffix(words[0], "/kaniko/executor"):
		cache, repo, dest := false, "", ""
		for i := 1; i < len(words); i++ {
			switch w := words[i]; {
			case w == "--cache" || w == "--cache=true":
				cache = true
			case w == "--cache-repo" && i+1 < len(words):
				i++
				repo = words[i]
			case strings.HasPrefix(w, "--cache-repo="):
				repo = strings.TrimPrefix(w, "--cache-repo=")
			case (w == "--destination" || w == "-d") && i+1 < len(words) && dest == "":
				i++
				dest = words[i]
			case strings.HasPrefix(w, "--destination=") && dest == "":
				dest = strings.TrimPrefix(w, "--destination=")
			}
		}
		if !cache {
			return ""
		}
		if repo == "" {
			// Kaniko derives the cache repository from the destination's,
			// without its tag.
			if dest == "" {
				repo = "<destination>/cache"
			} else {
				repo = imageRepository(resolve(strings.Trim(dest, `"'`))) + "/cache"
			}
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
	expanded := resolve(ref)
	for _, v := range perRunTagVars {
		if strings.Contains(expanded, "$"+v) || strings.Contains(expanded, "${"+v+"}") {
			return ""
		}
	}
	return ref
}

// imageRepository returns an image reference without its tag or digest.
func imageRepository(image string) string {
	// ${VAR:0:8} and ${VAR:-x} hold colons that don't start a tag.
	masked := []byte(image)
	depth := 0
	for i := 0; i < len(masked); i++ {
		switch {
		case masked[i] == '$' && i+1 < len(masked) && masked[i+1] == '{':
			depth++
			i++
		case masked[i] == '}' && depth > 0:
			depth--
		case depth > 0:
			masked[i] = '_'
		}
	}
	m := string(masked)
	if i := strings.Index(m, "@"); i >= 0 {
		image, m = image[:i], m[:i]
	}
	if i := strings.LastIndex(m, ":"); i > strings.LastIndex(m, "/") {
		image = image[:i]
	}
	return image
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

// slugEqualityRe matches a test of the ref slug against a branch name. Only a
// branch whose name slugs to it runs the job; another branch with that slug,
// such as Master, needs push access, which already lets its pipeline write
// to the registry with the job token.
var slugEqualityRe = mustCompilePrefiltered(`^\$\{?CI_COMMIT_REF_SLUG\}?\s*==\s*["'][a-z0-9-]+["']$`)

// protectedRefsList reports an only:/refs: list of nothing but main, master
// or tags.
func protectedRefsList(list *yaml.Node) bool {
	for _, item := range list.Content {
		switch item.Value {
		case "main", "master", "tags":
		default:
			return false
		}
	}
	return true
}

// jobProtectedOnly reports a job that runs on protected refs only,
// evaluated as GL013 and GL081 do (#1494): only: lists nothing but main,
// master or tags, or every rules entry that can run the job has an if: that
// restricts to the default branch, a named branch, a tag or a protected ref.
func jobProtectedOnly(job *yaml.Node) bool {
	if gl046ProtectedOnly(job) {
		return true
	}
	if only := parser.FindKey(job, "only"); only != nil && only.Kind == yaml.SequenceNode && len(only.Content) > 0 {
		return protectedRefsList(only)
	}
	// only: {refs: […], variables: […]} runs the job when a ref matches and
	// any variables: expression holds, so either part can restrict (#1550).
	if only := parser.FindKey(job, "only"); only != nil && only.Kind == yaml.MappingNode {
		if refs := parser.FindKey(only, "refs"); refs != nil && refs.Kind == yaml.SequenceNode && len(refs.Content) > 0 && protectedRefsList(refs) {
			return true
		}
		if vars := parser.FindKey(only, "variables"); vars != nil && vars.Kind == yaml.SequenceNode && len(vars.Content) > 0 {
			for _, item := range vars.Content {
				if item.Kind != yaml.ScalarNode || !ifRestrictsToProtected(item.Value) {
					return false
				}
			}
			return true
		}
		return false
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
		if cond == nil || !ifRestrictsToProtected(cond.Value) && !slugEqualityRe.MatchString(strings.TrimSpace(cond.Value)) {
			return false
		}
		running++
	}
	return running > 0
}
