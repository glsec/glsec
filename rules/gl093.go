// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl093 struct{}

// GL093 flags an interpreter run on a file whose extension is a data, asset or
// document type rather than a script, i.e. a payload disguised as a non-code
// file. The disguise is the point: a reviewer skims past a `.ttf` or `.png` as
// an asset, and running it through an interpreter is almost never legitimate.
// This is the shape of the PolinRider campaign (obfuscated JavaScript named
// `fa-brands-400.ttf`, run by a hidden task) and fits a `script:` line directly.
var GL093 = &gl093{}

func (r *gl093) ID() string { return "GL093" }

// gl093Interpreters are the programs that execute their script-file argument.
// The disguise is a payload passed to one of these as a file to run.
var gl093Interpreters = map[string]bool{
	"node": true, "nodejs": true, "deno": true, "bun": true,
	"python": true, "python2": true, "python3": true,
	"ruby": true, "perl": true, "php": true, "Rscript": true,
	"osascript": true, "pwsh": true, "powershell": true,
}

// gl093DisguisedExtRe matches a file operand that ends in a data, asset or
// document extension. It is matched on a single shell word with its quotes
// already removed, so it is anchored to the end of the word: `x.ttfoo` is not
// a `.ttf`.
var gl093DisguisedExtRe = mustCompilePrefiltered(
	`\.(?i:ttf|otf|woff2?|eot|png|jpe?g|gif|ico|bmp|svg|webp|pdf|csv|tsv|dat|bin|log|md|txt|lock)$`)

// gl093ExtAnywhereRe is a cheap line-level gate: a line with no disguised
// extension at all has nothing to flag and need not be parsed.
var gl093ExtAnywhereRe = mustCompilePrefiltered(
	`\.(?i:ttf|otf|woff2?|eot|png|jpe?g|gif|ico|bmp|svg|webp|pdf|csv|tsv|dat|bin|log|md|txt|lock)`)

func (r *gl093) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		v := line.Value
		if !gl093ExtAnywhereRe.MatchString(v) {
			return
		}
		// shellCommands splits the line into simple commands, dropping comments
		// (inline ones too), skipping here-document data, and descending into
		// the script of a local `sh -c`/`bash -c` so a disguised run hidden in a
		// child shell is seen as its own command (#1413).
		for _, cmd := range shellCommands(v) {
			operand, ok := gl093DisguisedFile(commandWords(cmd.text))
			if !ok {
				continue
			}
			ln, col := scriptLinePos(line, cmd.line)
			findings = append(findings, finding.Finding{
				RuleID:   "GL093",
				Severity: finding.Error,
				Job:      job,
				Message: "interpreter runs a non-script file (" + operand +
					") — an executable payload can hide behind a data, asset or document extension and still run; run only real script files, and remove this",
				File: file,
				Line: ln,
				Col:  col,
			})
		}
	})
	return findings
}

// gl093DisguisedFile reports the script file an interpreter command runs when
// that file has a disguised extension. words are the program and its arguments
// with wrappers (sudo, env, timeout, keywords, assignments) already stripped
// and quotes removed, so an interpreter named or operand quoted (`"node"
// fonts/x.ttf`, `node "fonts/x.ttf"`) resolves to the same words as the bare
// form; an interpreter that is only an argument to another command (echo,
// printf) never reaches command position and is not matched.
func gl093DisguisedFile(words []string) (string, bool) {
	name := commandName(words)
	if !gl093Interpreters[name] {
		return "", false
	}
	args := words[1:]
	// deno and bun run a script through a `run` subcommand (`deno run x.bin`),
	// which is not itself the operand. For the other interpreters `run` is an
	// ordinary filename (`python run.py`), so this is scoped to those two.
	if (name == "deno" || name == "bun") && len(args) > 0 && args[0] == "run" {
		args = args[1:]
	}
	// The script file is the first non-flag operand: inline code (`-e`, `-c`),
	// module invocations (`-m http.server`) and other flags are not script
	// files. Only that one operand is tested, so a flag's value or a later
	// argument cannot turn a plain run into a match.
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a, gl093DisguisedExtRe.MatchString(a)
	}
	return "", false
}
