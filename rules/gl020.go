// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl020 struct{}

var GL020 = &gl020{}

func (r *gl020) ID() string { return "GL020" }

// checksumRe matches checksum/signature verification commands.
var checksumRe = regexp.MustCompile(`\b(?:sha(?:256|512|1|224|384)sum|shasum|md5sum|gpg\s+--verify|cosign\s+verify|openssl\s+dgst)\b`)

func (r *gl020) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		lines := CollectJobScriptLines(job)

		// The first command that saves a download to disk.
		downloadLine, downloadCol := 0, 0
	scan:
		for _, l := range lines {
			cmds := shellCommands(l.Value)
			for i, cmd := range cmds {
				saved := savesDownload(withoutSudo(commandWords(cmd.text)))
				if !saved && isDownload(withoutSudo(commandWords(cmd.text))) {
					// To stdout, but into a file or an archive extractor.
					saved = redirectToFileRe.MatchString(cmd.text) ||
						cmd.piped && i+1 < len(cmds) && extractors[commandName(withoutSudo(commandWords(cmds[i+1].text)))]
				}
				if saved {
					downloadLine = parser.ScalarContentLine(l, cmd.line)
					if cmd.line == 0 {
						downloadCol = l.Column
					}
					break scan
				}
			}
		}
		if downloadLine == 0 {
			return
		}

		// If any line in the job has a checksum command, the job is considered safe.
		for _, l := range lines {
			if checksumRe.MatchString(l.Value) {
				return
			}
		}

		findings = append(findings, finding.Finding{
			RuleID:   "GL020",
			Severity: finding.Warn,
			Job:      name.Value,
			Message:  "job downloads a file with curl/wget but no checksum verification (sha256sum, gpg --verify, etc.) found in script",
			File:     file,
			Line:     downloadLine,
			Col:      downloadCol,
		})
	})

	return findings
}

// savesDownload reports whether a command is curl or wget writing what it
// fetches to a file. Output to stdout (-o -, wget -O -) or /dev/null, as in a
// readiness probe, is not a saved download.
func savesDownload(words []string) bool {
	words = withoutWrapper(words)
	switch commandName(words) {
	case "curl":
		return curlSaves(words[1:])
	case "wget":
		return wgetSaves(words[1:])
	}
	return false
}

func isDownload(words []string) bool {
	name := commandName(withoutWrapper(words))
	return name == "curl" || name == "wget"
}

// wrappers run the command given after their own options and numbers:
// timeout 60 curl …, retry 3 10 wget ….
var wrappers = map[string]bool{"timeout": true, "retry": true, "nice": true, "stdbuf": true, "xargs": true}

func withoutWrapper(words []string) []string {
	for wrappers[commandName(words)] {
		words = words[1:]
		for len(words) > 0 && (strings.HasPrefix(words[0], "-") || strings.Trim(words[0], "0123456789.smh") == "") {
			words = words[1:]
		}
	}
	return words
}

// redirectToFileRe matches stdout redirected to a file other than /dev/null.
var redirectToFileRe = regexp.MustCompile(`(?:^|[^0-9&>])>>?\s*(?:[^&\s/>]|/[^d\s]|/d[^e])`)

// extractors unpack what they read from stdin onto disk.
var extractors = map[string]bool{
	"tar": true, "bsdtar": true, "unzip": true, "gunzip": true, "zcat": true,
	"xz": true, "unxz": true, "xzcat": true, "bzcat": true, "zstd": true, "bunzip2": true, "cpio": true, "7z": true,
}

func curlSaves(args []string) bool {
	for i, a := range args {
		switch {
		case a == "-O" || a == "--remote-name" || a == "--remote-name-all":
			return true
		case a == "-o" || a == "--output":
			if i+1 < len(args) && savedOutput(args[i+1]) {
				return true
			}
		case strings.HasPrefix(a, "--output="):
			if savedOutput(strings.TrimPrefix(a, "--output=")) {
				return true
			}
		case strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--"):
			// A cluster of short options such as -sSLO or -sSLo file.
			if strings.ContainsRune(a, 'O') {
				return true
			}
			if j := strings.IndexByte(a, 'o'); j > 0 {
				out := a[j+1:]
				if out == "" && i+1 < len(args) {
					out = args[i+1]
				}
				if savedOutput(out) {
					return true
				}
			}
		}
	}
	return false
}

func wgetSaves(args []string) bool {
	for i, a := range args {
		switch {
		case a == "--spider":
			return false
		case a == "-O" || a == "--output-document":
			return i+1 < len(args) && savedOutput(args[i+1])
		case strings.HasPrefix(a, "--output-document="):
			return savedOutput(strings.TrimPrefix(a, "--output-document="))
		case strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--"):
			if j := strings.IndexByte(a, 'O'); j > 0 {
				out := a[j+1:]
				if out == "" && i+1 < len(args) {
					out = args[i+1]
				}
				return savedOutput(out)
			}
		}
	}
	return true
}

func savedOutput(target string) bool {
	return target != "" && target != "-" && target != "/dev/null"
}
