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

// gl011Match records the provenance of executed code for accurate diagnostics.
type gl011Match uint8

const (
	gl011None gl011Match = iota
	gl011EncodedPayload
	gl011RemoteDownload
)

func (r *gl011) ID() string { return "GL011" }

const shellAlt = `bash|sh|python[23]?|ruby|perl|node`

// pipeInto matches a pipe and any privilege or environment wrappers before
// the command it feeds: | sudo -E bash, | doas sh, | su -c sh,
// | runuser -u app -- bash, | sudo env FOO=1 bash (#1131). An option that
// takes a value (-u user) consumes it, so | sudo -u node tee x does not read
// the user name as the interpreter.
const pipeInto = `\|\s*(?:(?:sudo|doas|su|runuser|env)(?:\s+(?:` +
	`-[ugCDhprtU]\s+[^\s|;&-][^\s|;&]*` +
	`|-[abcdefijklmnoqsvwxyzABEFGHIJKLMNOPQRSTVWXYZ]|-[a-zA-Z]{2,}` +
	`|--[a-zA-Z][\w-]*(?:=[^\s|;&]*)?|--` +
	`|[A-Za-z_]\w*=[^\s|;&]*))*\s+)*`

var (
	// interpreterDashCRe matches a pipe into an interpreter that gets its code
	// from the command line, so the piped input is data: -c for shells and
	// python (python3 -c, bash -ec), -e/-p for node, -e/-E for perl and ruby,
	// also bundled (perl -ne, perl -lane) (#1057). -e alone is errexit for a
	// shell, so curl … | bash -e still runs the download.
	interpreterDashCRe = mustCompilePrefiltered(pipeInto + `(?:` +
		`(?:bash|sh|python[23]?)(?:\s+-[a-zA-Z]+)*?\s+-[a-zA-Z]*c\b` +
		`|node(?:\s+--?[a-zA-Z][a-zA-Z-]*)*?\s+(?:-e|--eval|-p|--print)\b` +
		`|(?:perl|ruby)(?:\s+-[a-zA-Z]+)*?\s+-[a-zA-Z]*[eE][a-zA-Z]*\b)`)
	// downloadToolRe matches curl or wget anywhere in a script line.
	downloadToolRe = mustCompilePrefiltered(`\b(?:curl|wget)\b`)
	// pipeToShellRe matches a pipe into a shell interpreter.
	pipeToShellRe = mustCompilePrefiltered(pipeInto + `(?:` + shellAlt + `)\b`)
	// processSubstRe matches bash process substitution: <(curl ...) or <(wget ...).
	processSubstRe = mustCompilePrefiltered(`<\s*\(\s*(?:curl|wget)\b`)
	// cmdSubstRe matches command substitution passed to a shell: bash -c "$(curl ...)".
	cmdSubstRe = mustCompilePrefiltered(`\b(?:bash|sh)\b.*\$\(\s*(?:curl|wget)\b`)
	// downloadSubstRe matches a curl/wget inside a command substitution: $(curl ...) or $(wget ...).
	downloadSubstRe = mustCompilePrefiltered(`\$\(\s*(?:curl|wget)\b`)
	// base64ExecRe matches a base64-decode piped straight into a shell, e.g.
	// echo "…" | base64 -d | bash — an inline-obfuscated payload with no download tool.
	base64ExecRe = mustCompilePrefiltered(`\bbase64\s+(?:-d|--decode)\b.*` + pipeInto + `(?:` + shellAlt + `)\b`)
	// hexExecRe matches a hex dump reversed by xxd -r and piped into a shell,
	// e.g. echo 6375… | xxd -r -p | bash — the same as base64ExecRe in hex.
	hexExecRe = mustCompilePrefiltered(`\bxxd\b[^|]*\s-[a-z]*r[a-z]*\b.*` + pipeInto + `(?:` + shellAlt + `)\b`)
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
	// The save must belong to the download command itself — [^|] keeps the -o/>
	// from crossing a pipe, so `wget … | gpg --dearmor -o keyring && sh -c '…'`
	// (a keyring install, where the -o is gpg's) is not read as a download saved
	// and executed (#1099).
	downloadThenExecRe = mustCompilePrefiltered(`\b(?:curl|wget)\b[^|]*(?:\s-o\b|\s--output\b|[^0-9&]>).*(?:;|&&)\s*(?:` + shellAlt + `)\s+\S`)
	// checksumGuardRe matches an integrity check on the same line; its presence means
	// the fetched code is verified before execution, so the line is not flagged.
	checksumGuardRe = mustCompilePrefiltered(`\b(?:sha256sum|sha512sum|shasum)\b|\bgpg\b.*--verify\b|\bcosign\b.*\bverify\b`)
	// quotedRe matches single- or double-quoted substrings, stripped before matching so
	// a "| bash" inside a string literal does not trigger.
	quotedRe = mustCompilePrefiltered(`"[^"]*"|'[^']*'`)
)

func (r *gl011) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(item *yaml.Node, file, job string) {
		// Each line of a block on its own: a curl on one line and a pipe into
		// an interpreter on another are two unrelated commands.
		for _, l := range logicalLines(item.Value) {
			kind := isDownloadExecute(l.text)
			if child := childShellDownloadExecute(l.text); child > kind {
				kind = child
			}
			if kind == gl011None {
				continue
			}
			message := fmt.Sprintf("script line downloads and executes remote code without integrity verification: %q", truncate(l.text, 80))
			if kind == gl011EncodedPayload {
				message = fmt.Sprintf("script line decodes and executes an opaque payload in an interpreter — the executable code is difficult to review: %q", truncate(l.text, 80))
			}
			f := finding.Finding{
				RuleID:   "GL011",
				Severity: finding.Error,
				Job:      job,
				Message:  message,
				File:     file,
				Line:     parser.ScalarContentLine(item, l.line),
			}
			if l.line == 0 {
				f.Col = item.Column
			}
			findings = append(findings, f)
		}
	})
	return findings
}

// childShellDownloadExecute classifies code executed by a new shell:
// sh -c "curl … | sh", docker run img sh -c '…', ssh host '…', including
// locally sourced encoded payloads. Quoted child scripts are checked as
// lines of their own (#1069).
func childShellDownloadExecute(line string) gl011Match {
	if !strings.Contains(line, "sh") {
		return gl011None
	}
	result := gl011None
	for _, cmd := range shellCommands(line) {
		_, inner, _, ok := childShellScript(commandWords(cmd.text))
		if !ok || len(inner) >= len(line) {
			continue
		}
		for _, l := range logicalLines(inner) {
			kind := isDownloadExecute(l.text)
			if child := childShellDownloadExecute(l.text); child > kind {
				kind = child
			}
			if kind == gl011RemoteDownload {
				return kind
			}
			if kind > result {
				result = kind
			}
		}
	}
	return result
}

// isDownloadExecute identifies the kind of execution, rather than merely
// whether the line matches. A download elsewhere on the line must not make
// an unrelated decoder pipeline appear to execute remote code (#1306).
func isDownloadExecute(line string) gl011Match {
	// An interpreter given its program on the command line reads stdin as
	// data: curl … | python3 -c "import json, sys; …" runs no downloaded code.
	stripped := interpreterDashCRe.ReplaceAllString(quotedRe.ReplaceAllString(line, ""), "| data")
	// An integrity check on the same line means the code is verified before running.
	if checksumGuardRe.MatchString(stripped) {
		return gl011None
	}
	// Command/process substitution intentionally lives inside quotes, so match the raw line.
	if processSubstRe.MatchString(line) || cmdSubstRe.MatchString(line) {
		return gl011RemoteDownload
	}
	// A download inside $(…) piped into an interpreter, e.g. echo "$(curl …)" | bash.
	// The quoted substitution is stripped above, so match the raw line.
	if downloadSubstRe.MatchString(line) && pipeToShellRe.MatchString(interpreterDashCRe.ReplaceAllString(line, "| data")) {
		return gl011RemoteDownload
	}
	if downloadFeedsInterpreter(stripped) {
		return gl011RemoteDownload
	}
	if base64ExecRe.MatchString(stripped) || hexExecRe.MatchString(stripped) {
		return gl011EncodedPayload
	}
	if hexEscapeRe.MatchString(line) && escapePrinterRe.MatchString(stripped) && pipeToShellRe.MatchString(stripped) {
		return gl011EncodedPayload
	}
	// PowerShell commands usually arrive quoted (pwsh -c "…"), so match the raw line.
	if psPipeExecRe.MatchString(line) || psArgExecRe.MatchString(line) {
		return gl011RemoteDownload
	}
	if downloadThenExecRe.MatchString(stripped) {
		return gl011RemoteDownload
	}
	return gl011None
}

// downloadFeedsInterpreter checks pipeline membership, not mere co-occurrence
// on a script line. Only a real curl/wget command upstream of the interpreter
// makes the executed bytes a remote download.
func downloadFeedsInterpreter(script string) bool {
	if !downloadToolRe.MatchString(script) || !pipeToShellRe.MatchString(script) {
		return false
	}
	cmds := shellCommands(script)
	for i := 0; i < len(cmds); {
		j := i
		for j < len(cmds)-1 && cmds[j].piped {
			j++
		}
		if j > i {
			hasDownload := false
			var pipeline strings.Builder
			for k := i; k <= j; k++ {
				if k > i {
					pipeline.WriteString(" | ")
				}
				pipeline.WriteString(cmds[k].text)
				if k < j {
					switch commandName(commandWords(cmds[k].text)) {
					case "curl", "wget":
						hasDownload = true
					}
				}
			}
			if hasDownload && pipeToShellRe.MatchString(pipeline.String()) {
				return true
			}
		}
		i = j + 1
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
