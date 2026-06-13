package rules

import (
	"fmt"
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl011 struct{}

var GL011 = &gl011{}

func (r *gl011) ID() string { return "GL011" }

const shellAlt = `bash|sh|python[23]?|ruby|perl|node`

var (
	// downloadToolRe matches curl or wget anywhere in a script line.
	downloadToolRe = regexp.MustCompile(`\b(?:curl|wget)\b`)
	// pipeToShellRe matches a pipe directly into a shell interpreter.
	pipeToShellRe = regexp.MustCompile(`\|\s*(?:` + shellAlt + `)\b`)
	// processSubstRe matches bash process substitution: <(curl ...) or <(wget ...).
	processSubstRe = regexp.MustCompile(`<\s*\(\s*(?:curl|wget)\b`)
	// cmdSubstRe matches command substitution passed to a shell: bash -c "$(curl ...)".
	cmdSubstRe = regexp.MustCompile(`\b(?:bash|sh)\b.*\$\(\s*(?:curl|wget)\b`)
	// downloadSubstRe matches a curl/wget inside a command substitution: $(curl ...) or $(wget ...).
	downloadSubstRe = regexp.MustCompile(`\$\(\s*(?:curl|wget)\b`)
	// base64ExecRe matches a base64-decode piped straight into a shell, e.g.
	// echo "…" | base64 -d | bash — an inline-obfuscated payload with no download tool.
	base64ExecRe = regexp.MustCompile(`\bbase64\s+(?:-d|--decode)\b.*\|\s*(?:` + shellAlt + `)\b`)
	// downloadThenExecRe matches a download saved to a file and executed on the same
	// line, e.g. curl … -o f && bash f, or curl … > f; sh f. The redirect alternative
	// uses [^0-9&]> so stderr/merge redirects (2>, &>) do not count as a save-to-file.
	downloadThenExecRe = regexp.MustCompile(`\b(?:curl|wget)\b.*(?:\s-o\b|\s--output\b|[^0-9&]>).*(?:;|&&)\s*(?:` + shellAlt + `)\s+\S`)
	// checksumGuardRe matches an integrity check on the same line; its presence means
	// the fetched code is verified before execution, so the line is not flagged.
	checksumGuardRe = regexp.MustCompile(`\b(?:sha256sum|sha512sum|shasum)\b|\bgpg\b.*--verify\b|\bcosign\b.*\bverify\b`)
	// quotedRe matches single- or double-quoted substrings, stripped before matching so
	// a "| bash" inside a string literal does not trigger.
	quotedRe = regexp.MustCompile(`"[^"]*"|'[^']*'`)
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
		if isDownloadExecute(item.Value) {
			findings = append(findings, finding.Finding{
				RuleID:   "GL011",
				Severity: finding.Error,
				Message:  fmt.Sprintf("script line downloads and executes remote code without integrity verification: %q", truncate(item.Value, 80)),
				File:     file,
				Line:     item.Line,
				Col:      item.Column,
			})
		}
	}
	return findings
}

func isDownloadExecute(line string) bool {
	stripped := quotedRe.ReplaceAllString(line, "")
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
	if downloadSubstRe.MatchString(line) && pipeToShellRe.MatchString(line) {
		return true
	}
	if downloadToolRe.MatchString(stripped) && pipeToShellRe.MatchString(stripped) {
		return true
	}
	if base64ExecRe.MatchString(stripped) {
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
