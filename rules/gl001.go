package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl001 struct{}

var GL001 = &gl001{}

func (r *gl001) ID() string { return "GL001" }

func (r *gl001) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	globalVars := parser.FindKey(mapping, "variables")
	resolveGlobal := func(name string) []string { return varValues(globalVars, name) }

	findings = append(findings, checkImageNode(parser.FindKey(mapping, "image"), file, resolveGlobal)...)
	findings = append(findings, checkServicesNode(parser.FindKey(mapping, "services"), file, resolveGlobal)...)

	if def := parser.FindKey(mapping, "default"); def != nil {
		findings = append(findings, checkImageNode(parser.FindKey(def, "image"), file, resolveGlobal)...)
		findings = append(findings, checkServicesNode(parser.FindKey(def, "services"), file, resolveGlobal)...)
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		resolve := jobVarResolver(name.Value, job, globalVars)
		for _, f := range checkImageNode(parser.FindKey(job, "image"), file, resolve) {
			f.Job = name.Value
			findings = append(findings, f)
		}
		for _, f := range checkServicesNode(parser.FindKey(job, "services"), file, resolve) {
			f.Job = name.Value
			findings = append(findings, f)
		}
	})

	return findings
}

// mutableTags is the set of well-known mutable image tags.
var mutableTags = map[string]bool{
	"latest":    true,
	"stable":    true,
	"edge":      true,
	"dev":       true,
	"main":      true,
	"master":    true,
	"nightly":   true,
	"rolling":   true,
	"canary":    true,
	"beta":      true,
	"alpha":     true,
	"lts":       true,
	"current":   true,
	"testing":   true,
	"oldstable": true,
}

// varResolver returns the values a variable defined in the file can take, or
// nil when the file does not define it.
type varResolver func(name string) []string

func checkImageNode(node *yaml.Node, file string, resolve varResolver) []finding.Finding {
	if node == nil {
		return nil
	}
	ref, line, col := imageRef(node)
	if ref == "" {
		return nil
	}
	return checkRefResolved(ref, line, col, file, resolve)
}

func checkServicesNode(node *yaml.Node, file string, resolve varResolver) []finding.Finding {
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		ref, line, col := imageRef(item)
		if ref == "" {
			continue
		}
		findings = append(findings, checkRefResolved(ref, line, col, file, resolve)...)
	}
	return findings
}

// checkRefResolved checks ref directly, or, when ref is a bare variable,
// each value the file assigns to that variable.
func checkRefResolved(ref string, line, col int, file string, resolve varResolver) []finding.Finding {
	if !isVarRef(ref) {
		return checkRef(ref, fmt.Sprintf("%q", ref), line, col, file)
	}
	var findings []finding.Finding
	seen := map[string]bool{}
	for _, v := range resolve(varRefName(ref)) {
		// Nested references are not followed.
		if seen[v] || v == "" || strings.Contains(v, "$") {
			continue
		}
		seen[v] = true
		findings = append(findings, checkRef(v, fmt.Sprintf("%q (= %q)", ref, v), line, col, file)...)
	}
	return findings
}

// jobVarResolver resolves a variable for a job: parallel:matrix values first,
// then the job's own variables:, then the top-level variables:. Global values
// are not used for hidden jobs (templates whose users may override them), for
// jobs that inherit through extends:/<<: (not resolved by glsec), or when
// inherit:variables excludes the name.
func jobVarResolver(jobName string, job, globalVars *yaml.Node) varResolver {
	jobVars := parser.FindKey(job, "variables")
	useGlobal := !strings.HasPrefix(jobName, ".") && !inheritsConfig(job) &&
		(jobVars == nil || parser.FindKey(jobVars, "<<") == nil)
	return func(name string) []string {
		fallback := varValues(jobVars, name)
		if fallback == nil && useGlobal && inheritsGlobalVar(job, name) {
			fallback = varValues(globalVars, name)
		}
		matrix, complete := matrixValues(job, name)
		if matrix == nil {
			return fallback
		}
		if !complete {
			matrix = append(matrix, fallback...)
		}
		return matrix
	}
}

// varValues returns the value of name in a variables: mapping, accepting both
// the short form and the long form with value:.
func varValues(vars *yaml.Node, name string) []string {
	if vars == nil {
		return nil
	}
	v := parser.FindKey(vars, name)
	if v != nil && v.Kind == yaml.MappingNode {
		v = parser.FindKey(v, "value")
	}
	if v == nil || v.Kind != yaml.ScalarNode {
		return nil
	}
	return []string{v.Value}
}

// matrixValues collects every value name takes across the job's
// parallel:matrix entries. complete is false when some entry does not set
// name, so the job- or file-level value also applies to that entry.
func matrixValues(job *yaml.Node, name string) (values []string, complete bool) {
	par := parser.FindKey(job, "parallel")
	if par == nil || par.Kind != yaml.MappingNode {
		return nil, false
	}
	matrix := parser.FindKey(par, "matrix")
	if matrix == nil || matrix.Kind != yaml.SequenceNode {
		return nil, false
	}
	complete = true
	for _, entry := range matrix.Content {
		v := parser.FindKey(entry, name)
		switch {
		case v == nil:
			complete = false
		case v.Kind == yaml.ScalarNode:
			values = append(values, v.Value)
		case v.Kind == yaml.SequenceNode:
			for _, item := range v.Content {
				if item.Kind == yaml.ScalarNode {
					values = append(values, item.Value)
				}
			}
		}
	}
	return values, complete
}

// inheritsGlobalVar reports whether inherit:variables lets the job see the
// top-level variable name.
func inheritsGlobalVar(job *yaml.Node, name string) bool {
	inherit := parser.FindKey(job, "inherit")
	if inherit == nil || inherit.Kind != yaml.MappingNode {
		return true
	}
	v := parser.FindKey(inherit, "variables")
	switch {
	case v == nil:
		return true
	case v.Kind == yaml.ScalarNode:
		return v.Value != "false"
	case v.Kind == yaml.SequenceNode:
		for _, item := range v.Content {
			if item.Value == name {
				return true
			}
		}
	}
	return false
}

// varRefName returns the variable name of a bare reference ($X or ${X}).
func varRefName(ref string) string {
	return strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(ref, "$"), "{"), "}")
}

// imageRef extracts the image reference and source location from a node.
// Handles both scalar ("node:latest") and mapping ({name: node:latest}) forms.
func imageRef(node *yaml.Node) (ref string, line, col int) {
	switch node.Kind {
	case yaml.ScalarNode:
		return node.Value, node.Line, node.Column
	case yaml.MappingNode:
		_, val := parser.FindKeyNode(node, "name")
		if val != nil {
			return val.Value, val.Line, val.Column
		}
	}
	return "", 0, 0
}

// isVarRef reports whether ref is entirely a shell variable expression
// ($MY_IMAGE or ${MY_IMAGE}). Such refs cannot be statically analysed
// for tag presence and must not be flagged as "no tag".
func isVarRef(ref string) bool {
	if len(ref) == 0 || ref[0] != '$' {
		return false
	}
	rest := ref[1:]
	if len(rest) > 0 && rest[0] == '{' {
		rest = strings.TrimSuffix(rest, "}")
		rest = rest[1:]
	}
	for _, ch := range rest {
		if (ch < 'A' || ch > 'Z') && (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '_' {
			return false
		}
	}
	return len(rest) > 0
}

// gitlabMacOSImage matches the VM images of GitLab-hosted macOS runners
// (macos-14-xcode-15). They are selected by name and cannot carry a tag.
var gitlabMacOSImage = regexp.MustCompile(`^macos-[0-9]+-xcode-[0-9]+$`)

// checkRef checks ref; label names the image in the message.
func checkRef(ref, label string, line, col int, file string) []finding.Finding {
	if strings.Contains(ref, "@sha256:") {
		return nil
	}
	if isVarRef(ref) || gitlabMacOSImage.MatchString(ref) {
		return nil
	}
	tag := imageTag(ref)
	if tag == "" {
		return []finding.Finding{{
			RuleID:   "GL001",
			Severity: finding.Error,
			Message:  fmt.Sprintf("image %s has no tag — defaults to latest (mutable)", label),
			File:     file, Line: line, Col: col,
		}}
	}
	if mutableTags[tag] {
		return []finding.Finding{{
			RuleID:   "GL001",
			Severity: finding.Error,
			Message:  fmt.Sprintf("image %s uses mutable tag %q — pin to a specific version or digest", label, tag),
			File:     file, Line: line, Col: col,
		}}
	}
	if isVersionlessTag(tag) {
		return []finding.Finding{{
			RuleID:   "GL001",
			Severity: finding.Warn,
			Message:  fmt.Sprintf("image %s uses tag %q, which names no version — it moves with every upstream release; pin a versioned variant (<version>-%s) or a digest", label, tag, tag),
			File:     file, Line: line, Col: col,
		}}
	}
	return nil
}

// isVersionlessTag reports whether tag carries no version at all: a variant
// (dind, alpine, slim) or a release codename (bookworm, jammy) that upstream
// rebuilds in place, like latest. A tag containing a variable is left alone,
// since its value is unknown statically.
func isVersionlessTag(tag string) bool {
	return !strings.ContainsAny(tag, "0123456789$")
}

// imageTag extracts the tag from an image reference.
// Returns empty string if no tag is present (implying latest).
func imageTag(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		return ""
	}
	last := ref
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		last = ref[i+1:]
	}
	if i := strings.Index(last, ":"); i >= 0 {
		return last[i+1:]
	}
	return ""
}
