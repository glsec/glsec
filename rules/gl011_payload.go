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

// minEmbeddedPayload is the shortest encoded literal reported as an embedded
// payload: short constants such as a base64 "user:password" or a test string
// stay below it (#1306).
const minEmbeddedPayload = 60

// embeddedPayloadFindings reports a script line that decodes a long literal
// base64 or hex payload into a file or a program other than a shell, such as
// echo <base64> | base64 -d > /tmp/.c (#1306). Decoded into a shell, the line
// is already reported as executing code; decoding a variable is left out.
func embeddedPayloadFindings(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(item *yaml.Node, file, job string) {
		if !strings.Contains(item.Value, "base64") && !strings.Contains(item.Value, "xxd") {
			return
		}
		for _, l := range logicalLines(item.Value) {
			if !decodesEmbeddedPayload(l.text) {
				continue
			}
			f := finding.Finding{
				RuleID:   "GL011",
				Severity: finding.Warn,
				Job:      job,
				Message:  fmt.Sprintf("script line decodes an embedded payload; its content is hidden from review — commit the decoded file in readable form, or download it and verify a checksum: %q", truncate(l.text, 80)),
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

// decodesEmbeddedPayload reports a pipeline that feeds a long encoded literal
// (echo, printf or a here-string) to a decoder whose output goes to a file or
// another program, not to a shell or interpreter.
func decodesEmbeddedPayload(line string) bool {
	cmds := shellCommands(line)
	for i := 0; i < len(cmds); {
		j := i
		for j < len(cmds)-1 && cmds[j].piped {
			j++
		}
		pipeline := cmds[i : j+1]
		i = j + 1
		for k, c := range pipeline {
			words := commandWords(c.text)
			hex, ok := payloadDecoder(words)
			if !ok {
				continue
			}
			literal := hereStringLiteral(c.text, hex)
			if !literal && k > 0 {
				literal = printsEncodedLiteral(commandWords(pipeline[k-1].text), hex)
			}
			if !literal {
				continue
			}
			if k+1 < len(pipeline) {
				// Into a shell or interpreter is executing code, which
				// base64ExecRe and hexExecRe already report.
				if interpreterNames[commandName(commandWords(pipeline[k+1].text))] {
					continue
				}
				return true
			}
			if writesToFile(c) {
				return true
			}
		}
	}
	return false
}

// interpreterNames are the programs that run decoded text as code.
var interpreterNames = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "ash": true,
	"python": true, "python2": true, "python3": true, "ruby": true, "perl": true, "node": true,
	"pwsh": true, "powershell": true, "source": true, ".": true, "eval": true,
}

// payloadDecoder reports a command that decodes base64 (base64 -d, --decode,
// macOS -D, openssl base64 -d) or reverses a hex dump (xxd -r), and whether it
// is the hex form.
func payloadDecoder(words []string) (hex, ok bool) {
	switch commandName(words) {
	case "base64":
		for _, w := range words[1:] {
			if w == "-d" || w == "--decode" || w == "-D" ||
				len(w) > 2 && w[0] == '-' && w[1] != '-' && strings.ContainsAny(w[1:], "dD") {
				return false, true
			}
		}
	case "openssl":
		hasBase64, hasDecode := false, false
		for _, w := range words[1:] {
			switch w {
			case "base64", "-base64", "-a":
				hasBase64 = true
			case "-d":
				hasDecode = true
			}
		}
		return false, hasBase64 && hasDecode
	case "xxd":
		for _, w := range words[1:] {
			if len(w) > 1 && w[0] == '-' && w[1] != '-' && strings.ContainsRune(w[1:], 'r') {
				return true, true
			}
		}
	}
	return false, false
}

// printsEncodedLiteral reports an echo or printf whose argument is a long
// encoded literal; a variable or substitution in it doesn't count.
func printsEncodedLiteral(words []string, hex bool) bool {
	switch commandName(words) {
	case "echo", "printf":
	default:
		return false
	}
	for _, w := range words[1:] {
		if isEncodedLiteral(w, hex) {
			return true
		}
	}
	return false
}

// hereStringLiteral reports a decoder fed a long literal through a
// here-string: base64 -d <<< "…".
func hereStringLiteral(text string, hex bool) bool {
	_, rest, ok := strings.Cut(text, "<<<")
	if !ok {
		return false
	}
	words := shellWords(rest)
	return len(words) > 0 && isEncodedLiteral(words[0], hex)
}

// isEncodedLiteral reports a word of at least minEmbeddedPayload base64 or hex
// characters and nothing else, with base64 padding allowed at the end.
func isEncodedLiteral(w string, hex bool) bool {
	if hex {
		w = strings.ReplaceAll(w, " ", "")
	} else {
		w = strings.TrimRight(w, "=")
	}
	if len(w) < minEmbeddedPayload {
		return false
	}
	for i := 0; i < len(w); i++ {
		c := w[i]
		switch {
		case '0' <= c && c <= '9', 'a' <= c && c <= 'f', 'A' <= c && c <= 'F':
		case !hex && ('g' <= c && c <= 'z' || 'G' <= c && c <= 'Z' || c == '+' || c == '/'):
		default:
			return false
		}
	}
	return true
}

// writesToFile reports a command whose output goes to a file: a > or >>
// redirection other than /dev/null or the standard streams.
func writesToFile(c shellCommand) bool {
	for _, target := range rcRedirectTargets(c.text) {
		if target != "/dev/null" && !strings.HasPrefix(target, "/dev/std") {
			return true
		}
	}
	return false
}
