// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/glsec/glsec/internal/parser"
)

// TestMetamorphic rewrites every fixture and corpus pipeline into forms that
// mean the same to GitLab and checks that glsec reports the same findings
// (rule, job and message; lines may move). A difference is either a rule that
// matches on spelling instead of meaning, or a rewrite that changes meaning
// in GitLab: the second kind goes into knownDifferences with the reason (#896).
func TestMetamorphic(t *testing.T) {
	var paths []string
	for _, dir := range []string{"fixtures", "corpus"} {
		abs, err := filepath.Abs(filepath.Join("..", "..", "testdata", dir))
		if err != nil {
			t.Fatal(err)
		}
		found, err := filepath.Glob(filepath.Join(abs, "*.yml"))
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, found...)
	}
	if len(paths) == 0 {
		t.Fatal("no pipelines in testdata")
	}

	used := map[string]bool{}
	for _, tr := range transforms {
		t.Run(tr.name, func(t *testing.T) {
			for _, path := range paths {
				name := filepath.Base(filepath.Dir(path)) + "/" + filepath.Base(path)
				t.Run(name, func(t *testing.T) {
					src, err := os.ReadFile(path) //nolint:gosec // G304: the repository's own test pipelines
					if err != nil {
						t.Fatal(err)
					}
					orig, errOut, origCode, ok := metamorphicFindings(t, string(src))
					if !ok {
						t.Fatalf("glsec can't scan the original:\n%s", errOut)
					}
					out, err := tr.apply(string(src))
					if errors.Is(err, errNotApplicable) {
						t.Skip("transformation doesn't apply")
					}
					if err != nil {
						t.Fatal(err)
					}
					got, errOut, gotCode, ok := metamorphicFindings(t, out)
					if !ok {
						t.Fatalf("glsec can't scan the rewritten pipeline:\n%s\n%s", errOut, out)
					}
					got = mapJobs(got, tr.jobName)
					var unexpected []string
					for _, d := range findingsDiff(orig, got) {
						key := tr.name + "/" + d.Rule
						if reason, ok := knownDifferences[key]; ok {
							used[key] = true
							t.Logf("known difference (%s): %s", reason, d)
							continue
						}
						unexpected = append(unexpected, d.String())
					}
					if len(unexpected) > 0 {
						t.Errorf("findings changed:\n%s\nrewritten pipeline:\n%s", strings.Join(unexpected, "\n"), out)
					}
					// When no finding diverged, an equivalent rewrite must not
					// change the selected policy: the CLI exit (0 vs 1) has to
					// match, so a severity flip that stops CI failing can't hide
					// behind an otherwise-unchanged finding set (#1416). Exit 2
					// is already a hard scan failure handled above.
					if len(unexpected) == 0 && origCode != gotCode {
						t.Errorf("exit code changed from %d to %d with no finding difference\nrewritten pipeline:\n%s", origCode, gotCode, out)
					}
				})
			}
		})
	}
	for key, reason := range knownDifferences {
		if !used[key] {
			t.Errorf("knownDifferences entry %s (%s) no longer differs anywhere: remove it", key, reason)
		}
	}
}

// knownDifferences lists "transform/rule" pairs whose findings change under a
// rewrite for a known reason: a rule gap with its issue, or a rewrite that
// isn't equivalent for that rule.
var knownDifferences = map[string]string{}

var errNotApplicable = errors.New("not applicable")

type transform struct {
	name  string
	apply func(src string) (string, error)
	// jobName maps a job name in the rewritten pipeline back to the original
	// one; nil means names don't change.
	jobName func(string) string
}

var transforms = []transform{
	{name: "reencode", apply: rewrite(func(*yaml.Node) bool { return true })},
	{name: "crlf", apply: func(src string) (string, error) {
		// Git may already check the file out with CRLF on Windows.
		return strings.ReplaceAll(strings.ReplaceAll(src, "\r\n", "\n"), "\n", "\r\n"), nil
	}},
	{name: "flow-style", apply: rewrite(flowStyle)},
	{name: "requote", apply: rewrite(requote)},
	{name: "script-form", apply: rewrite(scriptForm)},
	{name: "expand-anchors", apply: rewrite(expandAnchors)},
	{name: "reorder-jobs", apply: rewrite(reorderJobs)},
	{name: "extends", apply: rewrite(moveIntoExtends), jobName: func(name string) string {
		return strings.TrimPrefix(name, extendsPrefix)
	}},
	{name: "merge-anchors", apply: rewrite(moveIntoAnchor), jobName: func(name string) string {
		return strings.TrimPrefix(name, extendsPrefix)
	}},
}

// rewrite decodes every YAML document of src, applies fn to the last one
// (the pipeline; an earlier one is a spec: header) and encodes them again.
// fn reports whether it changed anything.
func rewrite(fn func(root *yaml.Node) bool) func(string) (string, error) {
	return func(src string) (string, error) {
		dec := yaml.NewDecoder(strings.NewReader(src))
		var docs []*yaml.Node
		for {
			var doc yaml.Node
			err := dec.Decode(&doc)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return "", err
			}
			docs = append(docs, &doc)
		}
		if len(docs) == 0 || len(docs[len(docs)-1].Content) == 0 {
			return "", errNotApplicable
		}
		if !fn(docs[len(docs)-1].Content[0]) {
			return "", errNotApplicable
		}
		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		for _, doc := range docs {
			if err := enc.Encode(doc); err != nil {
				return "", err
			}
		}
		if err := enc.Close(); err != nil {
			return "", err
		}
		return buf.String(), nil
	}
}

func walk(n *yaml.Node, fn func(*yaml.Node)) {
	fn(n)
	for _, c := range n.Content {
		walk(c, fn)
	}
}

// flowStyle writes every collection below the top level as [a, b] / {k: v}.
func flowStyle(root *yaml.Node) bool {
	changed := false
	for _, c := range root.Content {
		walk(c, func(n *yaml.Node) {
			if n.Kind == yaml.SequenceNode || n.Kind == yaml.MappingNode {
				n.Style |= yaml.FlowStyle
				changed = true
			}
		})
	}
	return changed
}

// requote cycles string scalars through plain, single and double quotes.
// Only scalars that already are strings: quoting 1 or true changes its type.
// Merge keys stay plain, since "<<" quoted is an ordinary key.
func requote(root *yaml.Node) bool {
	changed := false
	walk(root, func(n *yaml.Node) {
		if n.Kind != yaml.ScalarNode || n.ShortTag() != "!!str" || n.Value == "<<" ||
			n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 || strings.Contains(n.Value, "\n") {
			return
		}
		switch {
		case n.Style&yaml.DoubleQuotedStyle != 0:
			n.Style = yaml.SingleQuotedStyle
		case n.Style&yaml.SingleQuotedStyle != 0:
			n.Style = 0
		default:
			n.Style = yaml.DoubleQuotedStyle
		}
		changed = true
	})
	return changed
}

// scriptForm swaps script: "cmd" and script: [cmd].
func scriptForm(root *yaml.Node) bool {
	changed := false
	parser.EachJob(root, func(_, job *yaml.Node) {
		for _, key := range []string{"script", "before_script", "after_script"} {
			v := parser.FindKey(job, key)
			switch {
			case v == nil:
			case v.Kind == yaml.ScalarNode && v.Tag != "!reference":
				*v = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{{
					Kind: yaml.ScalarNode, Tag: "!!str", Value: v.Value, Style: v.Style,
				}}}
				changed = true
			case v.Kind == yaml.SequenceNode && len(v.Content) == 1 && v.Content[0].Kind == yaml.ScalarNode &&
				v.Content[0].Tag != "!reference":
				*v = *v.Content[0]
				changed = true
			}
		}
	})
	return changed
}

// expandAnchors replaces every alias with a copy of its anchor and every
// <<: merge with the merged keys, the way GitLab reads them: keys of the
// mapping itself win, then the first merged mapping.
func expandAnchors(root *yaml.Node) bool {
	changed := false
	var expand func(n *yaml.Node) *yaml.Node
	expand = func(n *yaml.Node) *yaml.Node {
		if n.Kind == yaml.AliasNode {
			changed = true
			return expand(deepCopy(n.Alias))
		}
		if n.Anchor != "" {
			n.Anchor = ""
			changed = true
		}
		for i, c := range n.Content {
			n.Content[i] = expand(c)
		}
		if n.Kind != yaml.MappingNode {
			return n
		}
		var own, merged []*yaml.Node
		has := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			if k := n.Content[i]; k.Value != "<<" || k.Style != 0 {
				own = append(own, k, n.Content[i+1])
				has[k.Value] = true
			}
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Value != "<<" || k.Style != 0 {
				continue
			}
			sources := []*yaml.Node{v}
			if v.Kind == yaml.SequenceNode {
				sources = v.Content
			}
			for _, src := range sources {
				for j := 0; j+1 < len(src.Content); j += 2 {
					if mk := src.Content[j]; !has[mk.Value] {
						merged = append(merged, deepCopy(mk), deepCopy(src.Content[j+1]))
						has[mk.Value] = true
					}
				}
			}
		}
		if len(own) != len(n.Content) {
			n.Content = append(merged, own...)
		}
		return n
	}
	expand(root)
	return changed
}

func deepCopy(n *yaml.Node) *yaml.Node {
	c := *n
	c.Content = make([]*yaml.Node, len(n.Content))
	for i, child := range n.Content {
		c.Content[i] = deepCopy(child)
	}
	return &c
}

// reorderJobs reverses the order of the top-level keys. Anchors are expanded
// first, since an alias must come after its anchor.
func reorderJobs(root *yaml.Node) bool {
	expandAnchors(root)
	if root.Kind != yaml.MappingNode || len(root.Content) < 4 {
		return false
	}
	var pairs [][2]*yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		pairs = append(pairs, [2]*yaml.Node{root.Content[i], root.Content[i+1]})
	}
	slices.Reverse(pairs)
	root.Content = root.Content[:0]
	for _, p := range pairs {
		root.Content = append(root.Content, p[0], p[1])
	}
	return true
}

const extendsPrefix = ".metamorphic-"

// moveIntoExtends moves every key of a visible job except script: into a
// hidden job and lets the job extend it, which GitLab merges back.
func moveIntoExtends(root *yaml.Node) bool {
	expandAnchors(root)
	type move struct {
		name string
		base *yaml.Node
	}
	var moves []move
	parser.EachJob(root, func(name, job *yaml.Node) {
		base, keep := splitScript(name, job)
		if base == nil {
			return
		}
		hidden := extendsPrefix + name.Value
		job.Content = append([]*yaml.Node{
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: "extends"},
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: hidden},
		}, keep...)
		moves = append(moves, move{hidden, base})
	})
	for _, m := range moves {
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: m.name}, m.base)
	}
	return len(moves) > 0
}

// moveIntoAnchor is moveIntoExtends with a YAML merge: the keys go into an
// anchored hidden job, placed before the job, which merges them with <<: *a.
func moveIntoAnchor(root *yaml.Node) bool {
	expandAnchors(root)
	if root.Kind != yaml.MappingNode {
		return false
	}
	jobs := map[*yaml.Node]bool{}
	parser.EachJob(root, func(name, _ *yaml.Node) { jobs[name] = true })
	var content []*yaml.Node
	moved := false
	for i := 0; i+1 < len(root.Content); i += 2 {
		name, job := root.Content[i], root.Content[i+1]
		var base *yaml.Node
		var keep []*yaml.Node
		if jobs[name] {
			base, keep = splitScript(name, job)
		}
		if base == nil {
			content = append(content, name, job)
			continue
		}
		anchor := fmt.Sprintf("metamorphic%d", i)
		base.Anchor = anchor
		job.Content = append([]*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "<<"},
			{Kind: yaml.AliasNode, Value: anchor, Alias: base},
		}, keep...)
		content = append(content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: extendsPrefix + name.Value}, base,
			name, job)
		moved = true
	}
	root.Content = content
	return moved
}

// splitScript splits a visible job into its script: pair and everything
// else; base is nil when the job has nothing to move.
func splitScript(name, job *yaml.Node) (base *yaml.Node, keep []*yaml.Node) {
	// spec: in the pipeline document itself looks like a job to EachJob.
	if strings.HasPrefix(name.Value, ".") || name.Value == "spec" {
		return nil, nil
	}
	base = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for i := 0; i+1 < len(job.Content); i += 2 {
		if job.Content[i].Value == "script" {
			keep = append(keep, job.Content[i], job.Content[i+1])
		} else {
			base.Content = append(base.Content, job.Content[i], job.Content[i+1])
		}
	}
	if len(base.Content) == 0 {
		return nil, nil
	}
	return base, keep
}

// TestMetamorphicWrappers runs every single script line of every fixture
// under a wrapper. The wrapper doesn't change what runs, so no rule may lose a
// finding; a rule that reads the command name without unwrapping does (#1149).
// New findings are fine: sudo is one itself.
func TestMetamorphicWrappers(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "testdata", "fixtures", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no fixtures")
	}
	for _, wrapper := range []string{"timeout 600", "nice -n 10", "sudo", "sudo -Hu node"} {
		t.Run(wrapper, func(t *testing.T) {
			for _, path := range paths {
				t.Run(filepath.Base(path), func(t *testing.T) {
					src, err := os.ReadFile(path) //nolint:gosec // G304: the repository's own test pipelines
					if err != nil {
						t.Fatal(err)
					}
					out, err := rewrite(func(root *yaml.Node) bool { return wrapScripts(root, wrapper) })(string(src))
					if errors.Is(err, errNotApplicable) {
						t.Skip("no script line to wrap")
					}
					if err != nil {
						t.Fatal(err)
					}
					orig, errOut, _, ok := metamorphicFindings(t, string(src))
					if !ok {
						t.Fatalf("glsec can't scan the original:\n%s", errOut)
					}
					got, errOut, _, ok := metamorphicFindings(t, out)
					if !ok {
						t.Fatalf("glsec can't scan the rewritten pipeline:\n%s\n%s", errOut, out)
					}
					count := map[[2]string]int{}
					for _, f := range got {
						count[[2]string{f.Rule, f.Job}]++
					}
					for _, f := range orig {
						key := [2]string{f.Rule, f.Job}
						if count[key]--; count[key] < 0 {
							t.Errorf("lost %s\nrewritten pipeline:\n%s", f, out)
						}
					}
				})
			}
		})
	}
}

// TestMetamorphicSplitTemplates moves each job's keys into a hidden template,
// as the extends transform does, and the templates into an included file.
// GitLab merges it back, so a finding of a job that runs must still be
// reported somewhere in the pipeline (#1154).
func TestMetamorphicSplitTemplates(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "testdata", "fixtures", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no fixtures")
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			src, err := os.ReadFile(path) //nolint:gosec // G304: the repository's own test pipelines
			if err != nil {
				t.Fatal(err)
			}
			extended, err := rewrite(moveIntoExtends)(string(src))
			if errors.Is(err, errNotApplicable) {
				t.Skip("no job to move")
			}
			if err != nil {
				t.Fatal(err)
			}
			root, templates, ok := splitTemplates(t, extended)
			if !ok {
				t.Skip("no hidden job to move")
			}
			orig, errOut, _, ok := metamorphicFindings(t, extended)
			if !ok {
				t.Fatalf("glsec can't scan the original:\n%s", errOut)
			}
			code, stdout, errOut := runCLI(t, map[string]string{".gitlab-ci.yml": root, "ci/templates.yml": templates},
				"--no-cache", "--no-repo-config", "--format", "json", ".gitlab-ci.yml")
			if code == 2 {
				t.Fatalf("glsec can't scan the split pipeline:\n%s\n%s", errOut, root)
			}
			var out struct {
				Findings []metamorphicFinding `json:"findings"`
			}
			if err := json.Unmarshal([]byte(stdout), &out); err != nil {
				t.Fatal(err)
			}
			count := map[string]int{}
			for _, f := range out.Findings {
				count[f.Rule]++
			}
			for _, f := range orig {
				if strings.HasPrefix(f.Job, ".") {
					continue
				}
				if count[f.Rule]--; count[f.Rule] < 0 {
					t.Errorf("lost %s\n%s\n---\n%s", f, root, templates)
				}
			}
		})
	}
}

// splitTemplates returns src without its hidden jobs, including a file that
// has them. A fixture with anchors can't be split: an alias doesn't reach
// across files.
func splitTemplates(t *testing.T, src string) (root, templates string, ok bool) {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil || doc.Kind != yaml.DocumentNode {
		return "", "", false
	}
	if strings.Contains(src, "\n---") || strings.Contains(src, "*") && strings.Contains(src, "&") {
		return "", "", false
	}
	mapping := doc.Content[0]
	var keep, moved []*yaml.Node
	hasInclude := false
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		k, v := mapping.Content[i], mapping.Content[i+1]
		switch {
		case strings.HasPrefix(k.Value, "."):
			moved = append(moved, k, v)
		case k.Value == "include":
			hasInclude = true
			keep = append(keep, k, v)
		default:
			keep = append(keep, k, v)
		}
	}
	if len(moved) == 0 || hasInclude {
		return "", "", false
	}
	mapping.Content = append([]*yaml.Node{
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: "include"},
		{Kind: yaml.ScalarNode, Tag: "!!str", Value: "ci/templates.yml"},
	}, keep...)
	r, err := yaml.Marshal(&doc)
	if err != nil {
		t.Fatal(err)
	}
	mapping.Content = moved
	m, err := yaml.Marshal(&doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(r), string(m), true
}

// unwrappable matches lines a wrapper can't run: builtins, compound commands,
// assignments and comments.
var unwrappable = regexp.MustCompile(`^(?:[A-Za-z_][A-Za-z0-9_]*=|[#({$\[.:!]|` +
	`(?:set|unset|export|cd|source|eval|exec|if|for|while|until|case|function|alias|read|local|` +
	`declare|typeset|readonly|trap|shopt|exit|return|ulimit|umask|wait|pushd|popd|test|true|false)(?:\s|$))`)

// wrapScripts puts wrapper in front of each single script line that runs a
// program.
func wrapScripts(root *yaml.Node, wrapper string) bool {
	changed := false
	wrap := func(n *yaml.Node) {
		if n.Kind == yaml.ScalarNode && n.Tag != "!reference" && !strings.Contains(strings.TrimSpace(n.Value), "\n") &&
			!unwrappable.MatchString(strings.TrimSpace(n.Value)) {
			n.Value = wrapper + " " + strings.TrimSpace(n.Value)
			changed = true
		}
	}
	parser.EachJob(root, func(_, job *yaml.Node) {
		for _, key := range []string{"script", "before_script", "after_script"} {
			v := parser.FindKey(job, key)
			switch {
			case v == nil:
			case v.Kind == yaml.SequenceNode:
				for _, item := range v.Content {
					wrap(item)
				}
			default:
				wrap(v)
			}
		}
	})
	return changed
}

type metamorphicFinding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Job      string `json:"job"`
	Message  string `json:"message"`
}

func (f metamorphicFinding) String() string {
	return fmt.Sprintf("%s %s [%s] %s", f.Rule, f.Severity, f.Job, f.Message)
}

// metamorphicFindings scans src as .gitlab-ci.yml; ok is false on exit 2, with
// stderr returned. code is the CLI exit status (0 when no error finding fails
// the run, 1 when one does), so callers can assert exit invariance too.
func metamorphicFindings(t *testing.T, src string) (findings []metamorphicFinding, stderr string, code int, ok bool) {
	t.Helper()
	code, stdout, errOut := runCLI(t, map[string]string{".gitlab-ci.yml": src},
		"--no-cache", "--no-repo-config", "--format", "json", ".gitlab-ci.yml")
	if code == 2 {
		return nil, errOut, code, false
	}
	var out struct {
		Findings []metamorphicFinding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("parse JSON output: %v", err)
	}
	for i := range out.Findings {
		out.Findings[i].Message = position.ReplaceAllString(out.Findings[i].Message, "$1 N")
	}
	return out.Findings, errOut, code, true
}

func TestMetamorphicFindingsExit2PreservesStderr(t *testing.T) {
	_, errOut, _, ok := metamorphicFindings(t, "job:\n  script: [unclosed\n")
	if ok {
		t.Fatal("expected ok=false for unscannable YAML (exit 2)")
	}
	if strings.TrimSpace(errOut) == "" {
		t.Fatal("expected non-empty stderr message when scan exits 2")
	}
}

// TestMetamorphicFindingsDiffSeverity proves the oracle's comparison now
// accounts for severity: two findings that agree on rule, job and message but
// differ only in severity must compare UNEQUAL, so a rewrite that silently
// downgrades a finding (e.g. image: node:latest -> image: "node:latest"
// turning an error into an info and flipping the CLI exit from 1 to 0) can no
// longer pass unnoticed (#1416).
func TestMetamorphicFindingsDiffSeverity(t *testing.T) {
	orig := []metamorphicFinding{{Rule: "GL001", Severity: "error", Job: "build", Message: "image uses the latest tag"}}
	got := []metamorphicFinding{{Rule: "GL001", Severity: "info", Job: "build", Message: "image uses the latest tag"}}

	diff := findingsDiff(orig, got)
	if len(diff) != 2 {
		t.Fatalf("severity-only difference must be detected: got %d diffs, want 2:\n%v", len(diff), diff)
	}
	var removed, added bool
	for _, d := range diff {
		switch {
		case !d.added && d.Severity == "error":
			removed = true
		case d.added && d.Severity == "info":
			added = true
		}
	}
	if !removed || !added {
		t.Fatalf("expected the error finding removed and the info finding added, got:\n%v", diff)
	}

	// Identical findings (severity included) must still compare equal, so the
	// added field does not make every equivalent rewrite look divergent.
	if diff := findingsDiff(orig, orig); len(diff) != 0 {
		t.Fatalf("identical findings must compare equal, got:\n%v", diff)
	}
}

// position matches the line and column numbers messages mention, which a
// rewrite may move.
var position = regexp.MustCompile(`\b(line|lines|column) \d+`)

func mapJobs(fs []metamorphicFinding, jobName func(string) string) []metamorphicFinding {
	if jobName == nil {
		return fs
	}
	out := make([]metamorphicFinding, len(fs))
	for i, f := range fs {
		f.Job = jobName(f.Job)
		f.Message = strings.ReplaceAll(f.Message, extendsPrefix, "")
		out[i] = f
	}
	return out
}

type findingDiff struct {
	metamorphicFinding
	added bool
}

func (d findingDiff) String() string {
	if d.added {
		return "+ " + d.metamorphicFinding.String()
	}
	return "- " + d.metamorphicFinding.String()
}

// findingsDiff compares two lists as multisets and returns the findings only
// one of them has: removed ones are in orig only, added ones in got only.
func findingsDiff(orig, got []metamorphicFinding) []findingDiff {
	count := map[metamorphicFinding]int{}
	for _, f := range orig {
		count[f]++
	}
	for _, f := range got {
		count[f]--
	}
	var out []findingDiff
	for f, n := range count {
		for ; n > 0; n-- {
			out = append(out, findingDiff{f, false})
		}
		for ; n < 0; n++ {
			out = append(out, findingDiff{f, true})
		}
	}
	slices.SortFunc(out, func(a, b findingDiff) int { return strings.Compare(a.String(), b.String()) })
	return out
}
