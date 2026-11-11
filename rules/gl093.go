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

// disguisedExecRe matches an interpreter (optionally with a path) run on a file
// argument that ends in a data/asset/document extension, past any flags. It is
// matched on the quote-masked line, so the interpreter must be a real command
// (line start or after a separator) and a quoted mention such as
// `echo "node payload.ttf"` is not read as one. Inline code (`node -e …`,
// `python -c …`) has no such file argument and is left alone.
var disguisedExecRe = mustCompilePrefiltered(
	`(?:^|[\s;&|(])` +
		`(?:\.{0,2}/(?:[\w.-]+/)*)?` +
		`(?:node|nodejs|deno|bun|python|python2|python3|ruby|perl|php|Rscript|osascript|pwsh|powershell)` +
		`(?:\s+run)?` + // deno run / bun run; backtracks for e.g. "python run.py"
		`(?:\s+-{1,2}[\w=.:/@-]+)*` +
		`\s+(?:(?:\.{0,2}/)?(?:[\w.@-]+/)*)?[\w.@-]+` +
		`\.(?i:ttf|otf|woff2?|eot|png|jpe?g|gif|ico|bmp|svg|webp|pdf|csv|tsv|dat|bin|log|md|txt|lock)` +
		`(?:\s|$|[;&|)])`,
)

func (r *gl093) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		v := line.Value
		if strings.HasPrefix(strings.TrimSpace(v), "#") {
			return
		}
		masked := maskShellQuotes(v)
		for _, m := range disguisedExecRe.FindAllStringIndex(masked, -1) {
			cmd := strings.TrimSpace(strings.Trim(v[m[0]:m[1]], ";&|()`"))
			ln, col := scriptMatchPos(line, m[0])
			findings = append(findings, finding.Finding{
				RuleID:   "GL093",
				Severity: finding.Error,
				Job:      job,
				Message: "interpreter runs a non-script file (" + cmd +
					") — an executable payload can hide behind a data, asset or document extension and still run; run only real script files, and remove this",
				File: file,
				Line: ln,
				Col:  col,
			})
		}
	})
	return findings
}
