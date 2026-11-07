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

type gl014 struct{}

var GL014 = &gl014{}

func (r *gl014) ID() string { return "GL014" }

// psEnvFormat lets the PowerShell env: enumeration pass through the cmdlets
// that keep every variable (Format-Table, Format-List, Out-String) before the
// output is redirected or teed. Filters that can drop variables, such as
// Select-Object, Where-Object or Select-String, are deliberately not allowed.
// Used by GL014 (#1161).
const psEnvFormat = `(?:\s*\|\s*(?i:format-table|format-list|out-string)(?:\s+-(?i:[a-z]+))?)*`

// psFileTarget matches the PowerShell cmdlets that write the pipeline's output
// to a file, with or without a path parameter (#1172).
const psFileTarget = `\|\s*(?i:out-file|set-content|add-content|tee-object)(?:\s+-(?i:filepath|literalpath|path|append|force))*\s+([^\s-]\S*)`

// envDumpRe matches a command that writes the whole environment to a file:
// env (also env -0/--null), printenv, export/export -p, set, declare/typeset
// bare or with only -p/-x, cat /proc/self/environ and the PowerShell env:
// enumeration (optionally through a formatting cmdlet),
// redirected with > or >>, piped into tee or into a PowerShell cmdlet that
// writes a file (see psFileTarget). The command has to
// start a command, so "cat .env > f", "printenv VAR > f" (a single
// variable), "set -e > f", "export FOO=bar > f" and "declare -a arr > f"
// don't match. Group 1, 2 or 3 is the target file.
// (?m) lets a command start on any line of a block scalar (#1161).
var envDumpRe = mustCompilePrefiltered(
	`(?m)(?:(?:^|[\s;&|(])(?:env(?:\s+(?:-0|--null))?|printenv|export\s+-p|` +
		`cat\s+/proc/(?:self|\$\$|[0-9]+)/environ)` +
		`|(?:^|[;&|(])\s*(?:set|export|(?:declare|typeset)(?:\s+-[px]+)?|` + psEnvDump + psEnvFormat + `))\s*` +
		`(?:>>?\s*(\S+)|\|\s*tee\s+(?:(?:-a|--append)\s+)?(\S+)|` + psFileTarget + `)`)

// Preserve pre-#1161 matches in quoted shell payloads and after comments
// containing quotes. Masking is only a guard for the newly added forms.
var legacyEnvDumpRe = mustCompilePrefiltered(
	`(?:^|[\s;&|(])(?:env|printenv|export\s+-p|cat\s+/proc/(?:self|\$\$|[0-9]+)/environ)\s*` +
		`(?:>>?\s*(\S+)|\|\s*tee\s+(?:(?:-a|--append)\s+)?(\S+))`)

// projectDirPrefixRe matches a target written relative to the project
// directory through its variable.
var projectDirPrefixRe = regexp.MustCompile(`^\$\{?CI_PROJECT_DIR\}?/`)

// dotenvValueRe matches NAME=$VALUE and NAME=${VALUE}. A longer expansion such
// as ${VALUE:+yes} doesn't write the value and doesn't match.
var dotenvValueRe = regexp.MustCompile(`(?:^|[\s"'])[A-Za-z_][A-Za-z0-9_]*=["']?\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))`)

// redirectTargetRe matches an output redirection of a command.
var redirectTargetRe = regexp.MustCompile(`(?:^|\s)>>?\s*(\S+)`)

func (r *gl014) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	def := parser.FindKey(parser.Unwrap(doc), "default")
	defArtifacts := def != nil && parser.FindKey(def, "artifacts") != nil
	in := NewInheritance(doc)

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if !defArtifacts && !in.Has(job, "artifacts") {
			return
		}
		job = in.Effective(job)
		artifacts := parser.FindKey(job, "artifacts")
		if artifacts == nil && def != nil {
			artifacts = parser.FindKey(def, "artifacts")
		}
		if artifacts == nil || artifacts.Kind != yaml.MappingNode {
			return
		}
		dotenv := dotenvArtifactNode(artifacts)
		eachJobScriptLine(job, func(item *yaml.Node) bool {
			script := blankCaseLabels(item.Value)
			if secret, target, line := dotenvSecret(script, dotenv); secret != "" {
				findings = append(findings, finding.Finding{
					RuleID:   "GL014",
					Severity: finding.Warn,
					Job:      name.Value,
					Message:  fmt.Sprintf("job %q writes secret variable %s to the dotenv report %q — pipeline users can read the file, and later jobs receive the value as a plain variable", name.Value, secret, target),
					File:     file,
					Line:     parser.ScalarContentLine(item, line),
					Col:      item.Column,
				})
				return false // one finding per job is enough
			}
			// Mask new forms, so a separator inside an echo string such
			// as `echo "hello; set > f"` is not read as a command boundary. The
			// target is taken from the original line so a quoted file name still
			// resolves (#1161).
			masked := maskShellQuotes(script)
			legacyStarts := map[int]bool{}
			for _, loc := range legacyEnvDumpRe.FindAllStringIndex(script, -1) {
				legacyStarts[loc[0]] = true
			}
			maskedStarts := map[int]bool{}
			for _, loc := range envDumpRe.FindAllStringSubmatchIndex(masked, -1) {
				maskedStarts[loc[0]] = true
			}
			for _, m := range envDumpRe.FindAllStringSubmatchIndex(script, -1) {
				if !legacyStarts[m[0]] && !maskedStarts[m[0]] {
					continue
				}
				target := ""
				for g := 2; g+1 < len(m); g += 2 {
					if m[g] >= 0 {
						target = script[m[g]:m[g+1]]
					}
				}
				var msg string
				switch {
				case dotenv != nil:
					msg = fmt.Sprintf("job %q dumps all environment variables to a dotenv artifact — CI_JOB_TOKEN and masked secrets are included and downloadable by any pipeline viewer", name.Value)
				case artifactCovers(artifacts, target):
					msg = fmt.Sprintf("job %q dumps all environment variables to %q, which its artifacts upload — CI_JOB_TOKEN and masked secrets are included and downloadable by anyone who can read the artifacts", name.Value, target)
				default:
					continue
				}
				findings = append(findings, finding.Finding{
					RuleID:   "GL014",
					Severity: finding.Warn,
					Job:      name.Value,
					Message:  msg,
					File:     file,
					Line:     item.Line,
					Col:      item.Column,
				})
				return false // one finding per job is enough
			}
			return true
		})
	})

	return findings
}

// eachJobScriptLine calls fn for every scalar script line of a job until fn
// returns false.
func eachJobScriptLine(job *yaml.Node, fn func(item *yaml.Node) bool) {
	blocks := []*yaml.Node{
		parser.FindKey(job, "script"),
		parser.FindKey(job, "before_script"),
		parser.FindKey(job, "after_script"),
		hookScriptNode(job),
	}
	blocks = append(blocks, parser.RunStepBlocks(job)...)
	for _, block := range blocks {
		if !isScriptList(block) {
			continue
		}
		for _, item := range block.Content {
			if item.Kind == yaml.ScalarNode && !fn(item) {
				return
			}
		}
	}
}

// dotenvArtifactNode returns the dotenv value node if the artifacts block sets
// reports:dotenv, otherwise nil.
func dotenvArtifactNode(artifacts *yaml.Node) *yaml.Node {
	reports := parser.FindKey(artifacts, "reports")
	if reports == nil {
		return nil
	}
	return parser.FindKey(reports, "dotenv")
}

// dotenvSecret returns the first secret variable an echo or printf in script
// writes as NAME=$SECRET into a file of the dotenv report, with that file and
// the index of the script line. The output of a substitution such as
// NAME=$(curl -H "$TOKEN" url) isn't the secret and doesn't count.
func dotenvSecret(script string, dotenv *yaml.Node) (secret, target string, line int) {
	if dotenv == nil || !strings.Contains(script, "=") {
		return "", "", 0
	}
	cmds := shellCommands(script)
	for i, cmd := range cmds {
		words := commandWords(cmd.text)
		if len(words) == 0 || (words[0] != "echo" && words[0] != "printf") {
			continue
		}
		targets := redirectTargets(cmd.text)
		if cmd.piped && i+1 < len(cmds) {
			if next := commandWords(cmds[i+1].text); len(next) > 1 && next[0] == "tee" {
				targets = append(targets, next[len(next)-1])
			}
		}
		target := firstDotenvFile(targets, dotenv)
		if target == "" {
			continue
		}
		for _, m := range dotenvValueRe.FindAllStringSubmatch(maskSingleQuoted(cmd.text), -1) {
			if name := m[1] + m[2]; isSecretName(name) {
				return name, target, cmd.line
			}
		}
	}
	return "", "", 0
}

func redirectTargets(text string) []string {
	var targets []string
	for _, m := range redirectTargetRe.FindAllStringSubmatch(text, -1) {
		targets = append(targets, m[1])
	}
	return targets
}

// firstDotenvFile returns the first of targets that dotenv, a scalar or a list
// of paths, names.
func firstDotenvFile(targets []string, dotenv *yaml.Node) string {
	entries := []*yaml.Node{dotenv}
	if dotenv.Kind == yaml.SequenceNode {
		entries = dotenv.Content
	}
	for _, target := range targets {
		for _, entry := range entries {
			if entry.Kind == yaml.ScalarNode && artifactPath(entry.Value) == artifactPath(target) {
				return artifactPath(target)
			}
		}
	}
	return ""
}

// artifactPath returns a file named in a script or in artifacts: relative to
// the project directory.
func artifactPath(p string) string {
	p = projectDirPrefixRe.ReplaceAllString(strings.Trim(p, `"'`), "")
	return strings.TrimPrefix(p, "./")
}

// artifactCovers reports whether an artifacts block uploads target, a file
// written by the job: untracked: true takes every file the job created, and
// paths: entries are globs relative to the project directory where ** spans
// directories and a directory takes everything below it. exclude: entries
// remove matching files again. A target outside the project directory or
// given by a variable is never matched against paths:.
func artifactCovers(artifacts *yaml.Node, target string) bool {
	target = artifactPath(target)
	known := target != "" && !strings.HasPrefix(target, "/") && !strings.Contains(target, "$") && !strings.Contains(target, "..")
	if known && artifactGlobsMatch(parser.FindKey(artifacts, "exclude"), target) {
		return false
	}
	if u := parser.FindKey(artifacts, "untracked"); parser.IsTrue(u) {
		return true
	}
	return known && artifactGlobsMatch(parser.FindKey(artifacts, "paths"), target)
}

// artifactGlobsMatch reports whether any glob in a paths: or exclude: list
// matches target or one of its parent directories.
func artifactGlobsMatch(list *yaml.Node, target string) bool {
	if list == nil || list.Kind != yaml.SequenceNode {
		return false
	}
	for _, item := range list.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		pattern := strings.TrimSuffix(strings.TrimPrefix(item.Value, "./"), "/")
		if pattern == "" || pattern == "." {
			return true
		}
		re := artifactGlobRe(pattern)
		for p := target; ; {
			if re.MatchString(p) {
				return true
			}
			i := strings.LastIndexByte(p, '/')
			if i < 0 {
				break
			}
			p = p[:i]
		}
	}
	return false
}

// artifactGlobRe translates an artifact glob to a regexp: ** matches across
// directories, * and ? within one path segment.
func artifactGlobRe(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch {
		case strings.HasPrefix(pattern[i:], "**/"):
			b.WriteString("(?:.*/)?")
			i += 2
		case strings.HasPrefix(pattern[i:], "**"):
			b.WriteString(".*")
			i++
		case pattern[i] == '*':
			b.WriteString("[^/]*")
		case pattern[i] == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}
