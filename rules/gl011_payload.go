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

// payloadEncoding is the alphabet a decoder command reverses.
type payloadEncoding int

const (
	encNone payloadEncoding = iota
	encBase64
	encBase32
	encHex
)

// embeddedPayloadFindings reports a script line that decodes a long literal
// base64, base32 or hex payload into a file or a program other than a shell,
// such as echo <base64> | base64 -d > /tmp/.c (#1306). When the decoded file
// is executed later in the same job (sh /tmp/.c), the finding is raised to an
// execution error, since the run code is hidden from review (#1346). Decoded
// straight into a shell, the line is already reported by isDownloadExecute;
// decoding a variable is left out.
func embeddedPayloadFindings(doc *yaml.Node, file string) []finding.Finding {
	// First pass: the files each job later executes as a script.
	executed := map[string]map[string]bool{}
	EachScriptLine(doc, file, func(item *yaml.Node, _, job string) {
		for _, l := range logicalLines(item.Value) {
			for _, p := range executedScriptPaths(l.text) {
				if executed[job] == nil {
					executed[job] = map[string]bool{}
				}
				executed[job][p] = true
			}
		}
	})

	var findings []finding.Finding
	EachScriptLine(doc, file, func(item *yaml.Node, file, job string) {
		if !strings.Contains(item.Value, "base64") &&
			!strings.Contains(item.Value, "base32") && !strings.Contains(item.Value, "xxd") {
			return
		}
		for _, l := range logicalLines(item.Value) {
			path, ok := embeddedPayloadFile(l.text)
			if !ok {
				continue
			}
			sev := finding.Warn
			msg := fmt.Sprintf("script line decodes an embedded payload; its content is hidden from review — commit the decoded file in readable form, or download it and verify a checksum: %q", truncate(l.text, 80))
			if path != "" && executed[job][path] {
				sev = finding.Error
				msg = fmt.Sprintf("script line decodes an embedded payload into %s, which the job runs as a script later; the executed code is hidden from review — commit it in readable form: %q", path, truncate(l.text, 80))
			}
			f := finding.Finding{
				RuleID:   "GL011",
				Severity: sev,
				Job:      job,
				Message:  msg,
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

// embeddedPayloadFile reports a pipeline that feeds a long encoded literal
// (echo, printf or a here-string) to a decoder whose output goes to a file or
// another program, not to a shell or interpreter. path is the file the decoded
// bytes are written to, or "" when they go into another program.
func embeddedPayloadFile(line string) (path string, ok bool) {
	cmds := shellCommands(line)
	for i := 0; i < len(cmds); {
		j := i
		for j < len(cmds)-1 && cmds[j].piped {
			j++
		}
		pipeline := cmds[i : j+1]
		i = j + 1
		for k, c := range pipeline {
			enc, isDecoder := payloadDecoder(commandWords(c.text))
			if !isDecoder {
				continue
			}
			literal := hereStringLiteral(c.text, enc)
			if !literal && k > 0 {
				literal = printsEncodedLiteral(commandWords(pipeline[k-1].text), enc)
			}
			if !literal {
				continue
			}
			if k+1 < len(pipeline) {
				// Into a shell or interpreter is executing code, which
				// isDownloadExecute already reports.
				if interpreterNames[commandName(commandWords(pipeline[k+1].text))] {
					continue
				}
				return "", true // into another program (tar, tee): no later file to correlate
			}
			if target := fileRedirectTarget(c); target != "" {
				return target, true
			}
		}
	}
	return "", false
}

// interpreterNames are the programs that run decoded text as code when it is
// piped into them.
var interpreterNames = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "ash": true,
	"python": true, "python2": true, "python3": true, "ruby": true, "perl": true, "node": true,
	"pwsh": true, "powershell": true, "source": true, ".": true, "eval": true,
}

// scriptInterpreters run a file given as their first non-option argument.
var scriptInterpreters = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "ash": true,
	"python": true, "python2": true, "python3": true, "ruby": true, "perl": true, "node": true,
}

// executedScriptPaths returns the files a line runs as a script: the argument
// of a shell/interpreter (sh f, bash -x f), and the target of . / source. A
// -c/-e command string is not a file, and arguments after the script are its
// data, not code, so `sh sweep data1 data2` runs only sweep (#1346).
func executedScriptPaths(line string) []string {
	var paths []string
	for _, c := range shellCommands(line) {
		words := commandWords(c.text)
		name := commandName(words)
		switch {
		case name == "." || name == "source":
			if len(words) > 1 {
				paths = append(paths, words[1])
			}
		case scriptInterpreters[name]:
			for idx := 1; idx < len(words); idx++ {
				w := words[idx]
				if w == "--" {
					if idx+1 < len(words) {
						paths = append(paths, words[idx+1])
					}
					break
				}
				if strings.HasPrefix(w, "-") {
					if runsCommandString(w) {
						break // -c/-e: the code is inline, not a file
					}
					continue
				}
				paths = append(paths, w)
				break
			}
		}
	}
	return paths
}

// runsCommandString reports an interpreter flag whose value is an inline
// command string rather than a script file: -c, -e, --eval and the like, also
// bundled as in sh -xc.
func runsCommandString(flag string) bool {
	switch flag {
	case "-c", "-e", "-E", "-p", "--eval", "--print", "--command":
		return true
	}
	return len(flag) > 1 && flag[0] == '-' && flag[1] != '-' && strings.ContainsRune(flag[1:], 'c')
}

// payloadDecoder reports a command that decodes an encoded payload and the
// alphabet it reverses: base64 (base64 -d/--decode, macOS -D, openssl base64
// -d), base32 (base32 -d/--decode), or a hex dump (xxd -r).
func payloadDecoder(words []string) (payloadEncoding, bool) {
	switch commandName(words) {
	case "base64", "base32":
		enc := encBase64
		if commandName(words) == "base32" {
			enc = encBase32
		}
		for _, w := range words[1:] {
			if w == "-d" || w == "--decode" || w == "-D" ||
				len(w) > 2 && w[0] == '-' && w[1] != '-' && strings.ContainsAny(w[1:], "dD") {
				return enc, true
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
		if hasBase64 && hasDecode {
			return encBase64, true
		}
	case "xxd":
		for _, w := range words[1:] {
			if len(w) > 1 && w[0] == '-' && w[1] != '-' && strings.ContainsRune(w[1:], 'r') {
				return encHex, true
			}
		}
	}
	return encNone, false
}

// printsEncodedLiteral reports an echo or printf whose argument is a long
// encoded literal; a variable or substitution in it doesn't count.
func printsEncodedLiteral(words []string, enc payloadEncoding) bool {
	switch commandName(words) {
	case "echo", "printf":
	default:
		return false
	}
	for _, w := range words[1:] {
		if isEncodedLiteral(w, enc) {
			return true
		}
	}
	return false
}

// hereStringLiteral reports a decoder fed a long literal through a
// here-string: base64 -d <<< "…".
func hereStringLiteral(text string, enc payloadEncoding) bool {
	_, rest, ok := strings.Cut(text, "<<<")
	if !ok {
		return false
	}
	words := shellWords(rest)
	return len(words) > 0 && isEncodedLiteral(words[0], enc)
}

// isEncodedLiteral reports a word of at least minEmbeddedPayload characters
// from the encoding's alphabet and nothing else, with base64/base32 padding
// allowed at the end.
func isEncodedLiteral(w string, enc payloadEncoding) bool {
	if enc == encHex {
		w = strings.ReplaceAll(w, " ", "")
	} else {
		w = strings.TrimRight(w, "=")
	}
	if len(w) < minEmbeddedPayload {
		return false
	}
	for i := 0; i < len(w); i++ {
		if !encodingChar(w[i], enc) {
			return false
		}
	}
	return true
}

// encodingChar reports whether c is in the encoding's alphabet.
func encodingChar(c byte, enc payloadEncoding) bool {
	hexDigit := '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
	switch enc {
	case encHex:
		return hexDigit
	case encBase32:
		// RFC 4648: A–Z and 2–7 (either case tolerated).
		return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '2' <= c && c <= '7'
	default: // encBase64
		return '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '+' || c == '/'
	}
}

// fileRedirectTarget returns the file a command's output is redirected to, or
// "" for none or only /dev/null and the standard streams.
func fileRedirectTarget(c shellCommand) string {
	for _, target := range rcRedirectTargets(c.text) {
		if target != "/dev/null" && !strings.HasPrefix(target, "/dev/std") {
			return strings.Trim(target, `"'`)
		}
	}
	return ""
}
