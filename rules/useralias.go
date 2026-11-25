// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"sort"
	"strings"

	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

// aliasSourceVars are the predefined variables an alias can carry: the GL002
// set plus CI_COMMIT_REF_SLUG, which GL015, GL046 and GL052 count too. Each
// rule still decides with its own list which of them it reports.
var aliasSourceVars = append([]string{"CI_COMMIT_REF_SLUG"}, userControlledVars...)

var aliasSourceRe = mustCompilePrefiltered(`\$\{?(` + strings.Join(aliasSourceVars, "|") + `)\b`)

// aliasRefRe matches a $NAME or ${NAME} reference.
var aliasRefRe = mustCompilePrefiltered(`\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*`)

// replaceRefs calls fn for every variable reference in s and puts its result
// in place of the reference.
func replaceRefs(s string, fn func(ref string) string) string {
	locs := aliasRefRe.FindAllStringIndex(s, -1)
	if locs == nil {
		return s
	}
	var b strings.Builder
	last := 0
	for _, l := range locs {
		// $$ is GitLab's escape for a literal $.
		if l[0] > 0 && s[l[0]-1] == '$' {
			continue
		}
		b.WriteString(s[last:l[0]])
		b.WriteString(fn(s[l[0]:l[1]]))
		last = l[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

// maxAliasDepth bounds how far a variable is followed through others.
const maxAliasDepth = 5

// userAliases holds, per job, the .gitlab-ci.yml variables whose value
// references a user-controlled predefined variable, directly or through other
// variables (#1504). GitLab expands those values recursively before the job
// runs, so BRANCH: $CI_COMMIT_REF_NAME makes $BRANCH user-controlled too.
type userAliases struct {
	in     *Inheritance
	global map[string]string
	jobs   map[string]*yaml.Node
	cache  map[string]map[string]string
}

func newUserAliases(doc *yaml.Node) *userAliases {
	mapping := parser.Unwrap(doc)
	a := &userAliases{
		in:    NewInheritance(doc),
		jobs:  map[string]*yaml.Node{},
		cache: map[string]map[string]string{},
	}
	a.global = literalVariables(parser.FindKey(mapping, "variables"))
	parser.EachJob(doc, func(name, job *yaml.Node) { a.jobs[name.Value] = job })
	return a
}

// literalVariables returns a variables: block's values as text. A value with
// expand: false is literal, so it references nothing.
func literalVariables(vars *yaml.Node) map[string]string {
	out := map[string]string{}
	if vars == nil || vars.Kind != yaml.MappingNode {
		return out
	}
	for i := 0; i+1 < len(vars.Content); i += 2 {
		k, v := vars.Content[i], vars.Content[i+1]
		switch v.Kind {
		case yaml.ScalarNode:
			out[k.Value] = v.Value
		case yaml.MappingNode:
			if e := parser.FindKey(v, "expand"); e != nil && parser.IsFalse(e) {
				out[k.Value] = ""
				continue
			}
			if val := parser.FindKey(v, "value"); val != nil && val.Kind == yaml.ScalarNode {
				out[k.Value] = val.Value
			}
		}
	}
	return out
}

// forJob returns the job's aliases: variable name to its value with every
// other variable in it expanded, for the variables whose expanded value
// references a user-controlled variable. A job's own variables (also
// through extends:) override the file's.
func (a *userAliases) forJob(job string) map[string]string {
	if m, ok := a.cache[job]; ok {
		return m
	}
	vars := map[string]string{}
	for k, v := range a.global {
		vars[k] = v
	}
	if node := a.jobs[job]; node != nil {
		for k, v := range literalVariables(parser.FindKey(a.in.Effective(node), "variables")) {
			vars[k] = v
		}
	}
	out := map[string]string{}
	for name := range vars {
		if v := expandVars(vars[name], vars, name, 0); aliasSourceRe.MatchString(v) {
			out[name] = v
		}
	}
	a.cache[job] = out
	return out
}

// expandVars expands the references in value that vars defines.
func expandVars(value string, vars map[string]string, self string, depth int) string {
	if depth >= maxAliasDepth || !strings.Contains(value, "$") {
		return value
	}
	return replaceRefs(value, func(ref string) string {
		name := strings.Trim(ref, "${}")
		v, ok := vars[name]
		if !ok || name == self {
			return ref
		}
		return expandVars(v, vars, name, depth+1)
	})
}

// expand replaces each alias in text with its expanded value, as GitLab does,
// and returns the aliases it replaced, sorted. Text without an alias is
// returned unchanged. A value with a quote, a newline or a # is replaced by
// the user-controlled variable it references only, so the script's quoting
// is left as it was.
func (a *userAliases) expand(text, job string) (string, []string) {
	aliases := a.forJob(job)
	if len(aliases) == 0 || !strings.Contains(text, "$") {
		return text, nil
	}
	seen := map[string]bool{}
	out := replaceRefs(text, func(ref string) string {
		name := strings.Trim(ref, "${}")
		v, ok := aliases[name]
		if !ok {
			return ref
		}
		seen[name] = true
		if strings.ContainsAny(v, "\"'\n#\\") {
			return aliasSourceRe.FindString(v)
		}
		return v
	})
	if len(seen) == 0 {
		return text, nil
	}
	used := make([]string, 0, len(seen))
	for name := range seen {
		used = append(used, "$"+name)
	}
	sort.Strings(used)
	return out, used
}

// mentionsVar reports whether text references name itself.
func mentionsVar(text, name string) bool {
	return strings.Contains(text, "$"+name) || strings.Contains(text, "${"+name)
}

// aliasNote is appended to a finding that was reached through aliases.
func aliasNote(used []string) string {
	return " (through variables: " + strings.Join(used, ", ") + ")"
}

// expandedLine returns a copy of a script line with its aliases expanded, or
// nil when it has none.
func (a *userAliases) expandedLine(line *yaml.Node, job string) (*yaml.Node, []string) {
	text, used := a.expand(line.Value, job)
	if used == nil {
		return nil, nil
	}
	cp := *line
	cp.Value = text
	return &cp, used
}
