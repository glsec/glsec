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

type gl011 struct{}

var GL011 = &gl011{}

func (r *gl011) ID() string { return "GL011" }

const shellAlt = `bash|sh|python[23]?|ruby|perl|node`

var (
	// interpreterDashCRe matches a pipe into an interpreter that gets its code
	// from the command line, so the piped input is data: -c for shells and
	// python (python3 -c, bash -ec), -e/-p for node, -e/-E for perl and ruby,
	// also bundled (perl -ne, perl -lane) (#1057). -e alone is errexit for a
	// shell, so curl … | bash -e still runs the download.
	interpreterDashCRe = mustCompilePrefiltered(`\|\s*(?:` +
		`(?:bash|sh|python[23]?)(?:\s+-[a-zA-Z]+)*?\s+-[a-zA-Z]*c\b` +
		`|node(?:\s+--?[a-zA-Z][a-zA-Z-]*)*?\s+(?:-e|--eval|-p|--print)\b` +
		`|(?:perl|ruby)(?:\s+-[a-zA-Z]+)*?\s+-[a-zA-Z]*[eE][a-zA-Z]*\b)`)
	// downloadToolRe matches curl or wget anywhere in a script line.
	downloadToolRe = mustCompilePrefiltered(`\b(?:curl|wget)\b`)
	// pipeToShellRe matches a pipe directly into a shell interpreter.
	pipeToShellRe = mustCompilePrefiltered(`\|\s*(?:` + shellAlt + `)\b`)
	// processSubstRe matches bash process substitution: <(curl ...) or <(wget ...).
	processSubstRe = mustCompilePrefiltered(`<\s*\(\s*(?:curl|wget)\b`)
	// cmdSubstRe matches command substitution passed to a shell: bash -c "$(curl ...)".
	cmdSubstRe = mustCompilePrefiltered(`\b(?:bash|sh)\b.*\$\(\s*(?:curl|wget)\b`)
	// downloadSubstRe matches a curl/wget inside a command substitution: $(curl ...) or $(wget ...).
	downloadSubstRe = mustCompilePrefiltered(`\$\(\s*(?:curl|wget)\b`)
	// base64ExecRe matches a base64-decode piped straight into a shell, e.g.
	// echo "…" | base64 -d | bash — an inline-obfuscated payload with no download tool.
	base64ExecRe = mustCompilePrefiltered(`\bbase64\s+(?:-d|--decode)\b.*\|\s*(?:` + shellAlt + `)\b`)
	// hexExecRe matches a hex dump reversed by xxd -r and piped into a shell,
	// e.g. echo 6375… | xxd -r -p | bash — the same as base64ExecRe in hex.
	hexExecRe = mustCompilePrefiltered(`\bxxd\b[^|]*\s-[a-z]*r[a-z]*\b.*\|\s*(?:` + shellAlt + `)\b`)
	// escapePrinterRe and hexEscapeRe together match printf '\x63\x75…' | sh or
	// echo -e "\x63…" | sh. The escapes sit inside quotes, so hexEscapeRe is
	// matched against the raw line.
	escapePrinterRe = mustCompilePrefiltered(`\b(?:printf|echo\s+-[a-zA-Z]*e[a-zA-Z]*)\b`)
	hexEscapeRe     = mustCompilePrefiltered(`\\x[0-9a-fA-F]{2}`)
	// psDownload matches a PowerShell download: Invoke-WebRequest and
	// Invoke-RestMethod with their aliases (curl and wget alias the former in
	// Windows PowerShell), or a WebClient DownloadString/DownloadData call.
	psDownload = `(?:\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|curl|wget)\b|\bnew-object\s+(?:system\.)?net\.webclient\s*\)\s*\.\s*download(?:string|data)\b)`
	// psPipeExecRe matches a download piped into Invoke-Expression:
	// iwr URL | iex, irm URL | Select … | Invoke-Expression. The pipeline ends
	// at the next ;, so a later statement's iex doesn't count.
	psPipeExecRe = mustCompilePrefiltered(`(?i)` + psDownload + `[^;]*\|\s*(?:iex|invoke-expression)\b`)
	// psArgExecRe matches Invoke-Expression whose argument is the download:
	// iex (irm URL), iex "& {$(irm URL)}", iex ((New-Object Net.WebClient).DownloadString(URL)).
	// Invoke-Expression on a local string has no download there and stays quiet.
	psArgExecRe = mustCompilePrefiltered(`(?i)\b(?:iex|invoke-expression)\b[\s("'&{$]*` + psDownload)
	// downloadThenExecRe matches a download saved to a file and executed on the same
	// line, e.g. curl … -o f && bash f, or curl … > f; sh f. The redirect alternative
	// uses [^0-9&]> so stderr/merge redirects (2>, &>) do not count as a save-to-file.
	downloadThenExecRe = mustCompilePrefiltered(`\b(?:curl|wget)\b.*(?:\s-o\b|\s--output\b|[^0-9&]>).*(?:;|&&)\s*(?:` + shellAlt + `)\s+\S`)
	// checksumGuardRe matches an integrity check on the same line; its presence means
	// the fetched code is verified before execution, so the line is not flagged.
	checksumGuardRe = mustCompilePrefiltered(`\b(?:sha256sum|sha512sum|shasum)\b|\bgpg\b.*--verify\b|\bcosign\b.*\bverify\b`)
	// quotedRe matches single- or double-quoted substrings, stripped before matching so
	// a "| bash" inside a string literal does not trigger.
	quotedRe = mustCompilePrefiltered(`"[^"]*"|'[^']*'`)
)

func (r *gl011) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptBlock(doc, file, func(node *yaml.Node, file, job string) {
		for _, f := range checkScriptDownloadExecute(node, file) {
			f.Job = job
			findings = append(findings, f)
		}
	})
	return findings
}

func checkScriptDownloadExecute(node *yaml.Node, file string) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		// Each line of a block on its own: a curl on one line and a pipe into
		// an interpreter on another are two unrelated commands.
		for _, l := range logicalLines(item.Value) {
			if !isDownloadExecute(l.text) && !childShellDownloadExecute(l.text) {
				continue
			}
			f := finding.Finding{
				RuleID:   "GL011",
				Severity: finding.Error,
				Message:  fmt.Sprintf("script line downloads and executes remote code without integrity verification: %q", truncate(l.text, 80)),
				File:     file,
				Line:     parser.ScalarContentLine(item, l.line),
			}
			if l.line == 0 {
				f.Col = item.Column
			}
			findings = append(findings, f)
		}
	}
	return findings
}

// childShellDownloadExecute reports a download-execute in the script a new
// shell runs: sh -c "curl … | sh", docker run img sh -c '…', ssh host '…'.
// Quoted text is stripped before isDownloadExecute looks for a pipe, so the
// script is checked as lines of its own (#1069).
func childShellDownloadExecute(line string) bool {
	if !strings.Contains(line, "sh") || !downloadToolRe.MatchString(line) {
		return false
	}
	for _, cmd := range shellCommands(line) {
		_, inner, _, ok := childShellScript(withoutSudo(commandWords(cmd.text)))
		if !ok || len(inner) >= len(line) {
			continue
		}
		for _, l := range logicalLines(inner) {
			if isDownloadExecute(l.text) || childShellDownloadExecute(l.text) {
				return true
			}
		}
	}
	return false
}

func isDownloadExecute(line string) bool {
	// An interpreter given its program on the command line reads stdin as
	// data: curl … | python3 -c "import json, sys; …" runs no downloaded code.
	stripped := interpreterDashCRe.ReplaceAllString(quotedRe.ReplaceAllString(line, ""), "| data")
	// An integrity check on the same line means the code is verified before running.
	if checksumGuardRe.MatchString(stripped) {
		return false
	}
	// Command/process substitution intentionally lives inside quotes, so match the raw line.
	if processSubstRe.MatchString(line) || cmdSubstRe.MatchString(line) {
		return true
	}
	// A download inside $(…) piped into an interpreter, e.g. echo "$(curl …)" | bash.
	// The quoted substitution is stripped above, so match the raw line.
	if downloadSubstRe.MatchString(line) && pipeToShellRe.MatchString(interpreterDashCRe.ReplaceAllString(line, "| data")) {
		return true
	}
	if downloadToolRe.MatchString(stripped) && pipeToShellRe.MatchString(stripped) {
		return true
	}
	if base64ExecRe.MatchString(stripped) || hexExecRe.MatchString(stripped) {
		return true
	}
	if hexEscapeRe.MatchString(line) && escapePrinterRe.MatchString(stripped) && pipeToShellRe.MatchString(stripped) {
		return true
	}
	// PowerShell commands usually arrive quoted (pwsh -c "…"), so match the raw line.
	if psPipeExecRe.MatchString(line) || psArgExecRe.MatchString(line) {
		return true
	}
	return downloadThenExecRe.MatchString(stripped)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
