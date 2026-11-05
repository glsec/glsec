// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path"
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

// placeholderRCFiles are config files whose readers resolve ${VAR}
// placeholders when they load them: npm and Yarn. A job that writes one with
// the placeholder escaped uploads the placeholder, not the token (#1171).
// .netrc, .pypirc and .docker/config.json are read literally and don't count.
var placeholderRCFiles = map[string]bool{".npmrc": true, ".yarnrc.yml": true}

// literalWriters are the commands whose output is the text of their own
// arguments, so the script shows what they write.
var literalWriters = map[string]bool{"echo": true, "printf": true}

var rcVarRefRe = regexp.MustCompile(`^\$\{?([A-Za-z_][A-Za-z0-9_]*)`)

// writesPlaceholderOnly reports whether artifactPath, an npm or Yarn config
// file listed in the artifacts block, is written by the script of every job
// that uploads it with literal text expanding no secret-like variable:
// `echo '…:_authToken=${NPM_TOKEN}'` or `echo "…:_authToken=\${CI_JOB_TOKEN}"`.
// The jobs are those whose artifacts:paths, followed along extends:, is this
// block's, so a template's paths count for the jobs that extend it. A file a
// job doesn't write, or writes in a way glsec can't read, is not exempt, nor
// is a block under default: (in is nil) (#1171).
func writesPlaceholderOnly(doc *yaml.Node, in *Inheritance, artifacts *yaml.Node, artifactPath string) bool {
	if in == nil || !placeholderRCFiles[strings.ToLower(path.Base(artifactPath))] ||
		strings.HasPrefix(artifactPath, "/") || strings.Contains(artifactPath, "../") {
		return false
	}
	paths := parser.FindKey(artifacts, "paths")
	if paths == nil {
		return false
	}
	target := normalizeWritePath(artifactPath)
	users := 0
	ok := true
	parser.EachJob(doc, func(name, job *yaml.Node) {
		if !ok || !runsInheritedJob(in, name, job) || effectivePaths(in, job) != paths {
			return
		}
		users++
		ok = jobWritesPlaceholderOnly(in, job, target)
	})
	return ok && users > 0
}

// effectivePaths returns the artifacts:paths that applies to job along its
// extends: chain.
func effectivePaths(in *Inheritance, job *yaml.Node) *yaml.Node {
	for _, a := range in.Chain(job, "artifacts") {
		if p := parser.FindKey(a, "paths"); p != nil {
			return p
		}
	}
	return nil
}

func jobWritesPlaceholderOnly(in *Inheritance, job *yaml.Node, target string) bool {
	items, ok := jobScriptItems(in, job)
	if !ok {
		return false
	}
	wrote := false
	for _, item := range items {
		w, ok := placeholderWrites(item, target)
		if !ok {
			return false
		}
		wrote = wrote || w
	}
	return wrote
}

// jobScriptItems returns the scalar items of the before_script, script,
// after_script and hooks that apply to the job. ok is false when a script
// can't be read here: an unresolved !reference, or run: steps.
func jobScriptItems(in *Inheritance, job *yaml.Node) (items []string, ok bool) {
	if in.Key(job, "run") != nil {
		return nil, false
	}
	var walk func(n *yaml.Node) bool
	walk = func(n *yaml.Node) bool {
		switch {
		case n == nil:
			return true
		case parser.IsReference(n):
			return false
		case n.Kind == yaml.ScalarNode:
			items = append(items, n.Value)
			return true
		case n.Kind == yaml.SequenceNode:
			for _, c := range n.Content {
				if !walk(c) {
					return false
				}
			}
			return true
		}
		return false
	}
	for _, key := range []string{"before_script", "script", "after_script"} {
		if !walk(in.Key(job, key)) {
			return nil, false
		}
	}
	if hooks := in.Key(job, "hooks"); hooks != nil && !walk(parser.FindKey(hooks, "pre_get_sources_script")) {
		return nil, false
	}
	return items, true
}

// placeholderWrites scans one script item. wrote reports a write to target;
// ok is false when the item writes target with an expanded secret, writes it
// with a command whose output glsec can't see, changes directory, or may
// write it through npm or Yarn themselves.
func placeholderWrites(item, target string) (wrote, ok bool) {
	cmds := shellCommands(item)
	for i, c := range cmds {
		words := withoutSudo(commandWords(c.text))
		name := commandName(words)
		switch name {
		case "cd", "pushd", "popd":
			return false, false
		case "npm", "yarn", "pnpm":
			if rcWritingSubcommand(words[1:]) {
				return false, false
			}
		}
		hits, unknown := writeTargets(c.text, words, name, target)
		if !hits && !unknown {
			if mentionsPath(words, target) {
				// sed -i, cp, mv, envsubst …: not literal text.
				return false, false
			}
			continue
		}
		content, literal := writtenContent(item, cmds, i, name)
		if !literal || expandsSecret(content.text, content.heredoc) {
			return false, false
		}
		wrote = wrote || hits
	}
	return wrote, true
}

// rcWritingSubcommand reports `npm config set`, `npm set`, `npm login` and the
// like, which write a config file themselves, possibly the project's.
func rcWritingSubcommand(args []string) bool {
	for i, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		switch a {
		case "set", "login", "adduser", "add-user":
			return true
		case "config", "c":
			for _, b := range args[i+1:] {
				if !strings.HasPrefix(b, "-") {
					return b == "set"
				}
			}
			return false
		}
		return false
	}
	return false
}

type rcContent struct {
	text    string
	heredoc bool // text is a here-document body that expands variables
}

// writtenContent returns the text a writing command produces when it is
// literal: echo or printf, cat of a here-document, tee fed by one of those, or
// a { …; } or ( … ) group of them.
func writtenContent(item string, cmds []shellCommand, i int, name string) (rcContent, bool) {
	c := cmds[i]
	if name == "tee" {
		if i == 0 || !cmds[i-1].piped {
			return rcContent{}, false
		}
		prev := cmds[i-1]
		return literalCommand(item, prev.text)
	}
	t := strings.TrimSpace(c.text)
	if strings.HasPrefix(t, "}") || strings.HasPrefix(t, ")") {
		var parts []string
		depth := 0
		heredoc := false
		for j := i; j >= 0; j-- {
			mt := strings.TrimSpace(cmds[j].text)
			if strings.HasPrefix(mt, "}") || strings.HasPrefix(mt, ")") {
				depth++
				mt = strings.TrimSpace(mt[1:])
			}
			opener := strings.HasPrefix(mt, "{") || strings.HasPrefix(mt, "(")
			if opener {
				depth--
			}
			if j != i && commandName(withoutSudo(commandWords(mt))) != "" {
				content, ok := literalCommand(item, mt)
				if !ok {
					return rcContent{}, false
				}
				parts = append(parts, content.text)
				heredoc = heredoc || content.heredoc
			}
			if depth == 0 {
				return rcContent{text: strings.Join(parts, "\n"), heredoc: heredoc}, true
			}
		}
		return rcContent{}, false
	}
	return literalCommand(item, c.text)
}

// literalCommand returns the text an echo, printf or here-document cat writes.
// For an unquoted here-document the whole item stands in for its body, which
// shellCommands drops.
func literalCommand(item, text string) (rcContent, bool) {
	name := commandName(withoutSudo(commandWords(text)))
	if literalWriters[name] {
		return rcContent{text: text}, true
	}
	if name != "cat" {
		return rcContent{}, false
	}
	i := strings.Index(text, "<<")
	if i < 0 {
		return rcContent{}, false
	}
	m := heredocRe.FindStringSubmatch(text[i:])
	if m == nil {
		return rcContent{}, false
	}
	if m[3] != "" && !strings.HasPrefix(strings.TrimLeft(m[0][2:], "- \t"), `\`) {
		return rcContent{text: item, heredoc: true}, true
	}
	return rcContent{text: text}, true
}

// writeTargets reports whether the command redirects or tees into target, and
// whether it writes a path glsec can't resolve, such as "$NPMRC".
func writeTargets(text string, words []string, name, target string) (hits, unknown bool) {
	var paths []string
	paths = append(paths, redirectTargets(text)...)
	if name == "tee" {
		for _, w := range words[1:] {
			if !strings.HasPrefix(w, "-") && !isRedirectWord(w) {
				paths = append(paths, w)
			}
		}
	}
	for _, p := range paths {
		n := normalizeWritePath(p)
		switch {
		case n == target:
			hits = true
		case strings.Contains(n, "$"):
			unknown = true
		}
	}
	return hits, unknown
}

func isRedirectWord(w string) bool {
	return strings.ContainsAny(w, "<>")
}

// redirectTargets returns the files a command's output redirections write:
// `> f`, `>> f`, `>| f`, `2> f`, `&> f`. Duplications such as 2>&1 are not
// files.
func redirectTargets(text string) []string {
	var out []string
	var quote byte
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case quote != 0:
			if c == '\\' && quote == '"' {
				i++
			} else if c == quote {
				quote = 0
			}
		case c == '\\':
			i++
		case c == '\'' || c == '"':
			quote = c
		case c == '>':
			j := i + 1
			if j < len(text) && (text[j] == '>' || text[j] == '|') {
				j++
			}
			if j < len(text) && text[j] == '&' {
				i = j
				continue
			}
			for j < len(text) && isShellSpace(text[j]) {
				j++
			}
			k := j
			var q byte
			for ; k < len(text); k++ {
				d := text[k]
				if q != 0 {
					if d == q {
						q = 0
					}
					continue
				}
				if d == '\'' || d == '"' {
					q = d
					continue
				}
				if isShellSpace(d) || strings.IndexByte(";|&<>()", d) >= 0 {
					break
				}
			}
			if w := shellWords(text[j:k]); len(w) == 1 {
				out = append(out, w[0])
			}
			i = k - 1
		}
	}
	return out
}

// mentionsPath reports whether a word of the command names target, as in
// `cp ~/.npmrc .npmrc` or `sed -i … .npmrc`.
func mentionsPath(words []string, target string) bool {
	if len(words) == 0 || literalWriters[commandName(words)] {
		return false
	}
	for _, w := range words[1:] {
		if normalizeWritePath(w) == target {
			return true
		}
	}
	return false
}

// normalizeWritePath maps the spellings of a project-relative path to one:
// ./.npmrc, $CI_PROJECT_DIR/.npmrc and .npmrc are the same file.
func normalizeWritePath(p string) string {
	for {
		switch {
		case strings.HasPrefix(p, "./"):
			p = p[2:]
		case strings.HasPrefix(p, "$CI_PROJECT_DIR/"):
			p = p[len("$CI_PROJECT_DIR/"):]
		case strings.HasPrefix(p, "${CI_PROJECT_DIR}/"):
			p = p[len("${CI_PROJECT_DIR}/"):]
		default:
			if p == "" {
				return p
			}
			return path.Clean(p)
		}
	}
}

// expandsSecret reports whether text expands a secret-like variable, or a
// command substitution whose output glsec can't see. Single-quoted text and
// \$ are literal. In a here-document body (heredoc) quotes are literal too,
// so only \$ is.
func expandsSecret(text string, heredoc bool) bool {
	var quote byte
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case c == '\\':
			i++
		case (c == '\'' || c == '"') && !heredoc:
			switch quote {
			case c:
				quote = 0
			case 0:
				quote = c
			}
		case c == '`':
			return true
		case c == '$':
			if strings.HasPrefix(text[i:], "$(") {
				return true
			}
			if m := rcVarRefRe.FindStringSubmatch(text[i:]); m != nil {
				if isSecretName(m[1]) || predefinedSecrets[m[1]] {
					return true
				}
			}
		}
	}
	return false
}
