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

	download := nodeMemo[int]{} // item line of the first saved download, or -1
	checksum := nodeMemo[bool]{}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		lines := CollectJobScriptLines(job)

		// The first command that saves a download to disk.
		downloadLine, downloadCol := 0, 0
		for _, l := range lines {
			at := download.get(l, func() int { return firstSavedDownload(l.Value) })
			if at >= 0 {
				downloadLine = parser.ScalarContentLine(l, at)
				if at == 0 {
					downloadCol = l.Column
				}
				break
			}
		}
		if downloadLine == 0 {
			return
		}

		// If any line in the job has a checksum command, the job is considered safe.
		for _, l := range lines {
			if checksum.get(l, func() bool { return checksumRe.MatchString(l.Value) }) {
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

// firstSavedDownload returns the index of the item line whose command saves a
// download to disk, or -1.
func firstSavedDownload(script string) int {
	cmds := shellCommands(script)
	for i, cmd := range cmds {
		saved := savesDownload(withoutSudo(commandWords(cmd.text)))
		if !saved && isDownload(withoutSudo(commandWords(cmd.text))) {
			// To stdout, but into a file or an archive extractor.
			saved = redirectToFileRe.MatchString(cmd.text) ||
				cmd.piped && i+1 < len(cmds) && extractors[commandName(withoutSudo(commandWords(cmds[i+1].text)))]
		}
		if saved {
			return cmd.line
		}
	}
	return -1
}

// savesDownload reports whether a command is curl or wget writing what it
// fetches to a file. Output to stdout (-o -, wget -O -) or /dev/null, as in a
// readiness probe, is not a saved download.
func savesDownload(words []string) bool {
	words = withoutWrapper(words)
	if sendsData(words) {
		return false
	}
	switch commandName(words) {
	case "curl":
		return curlSaves(words[1:])
	case "wget":
		return wgetSaves(words[1:])
	}
	return false
}

func isDownload(words []string) bool {
	if sendsData(withoutWrapper(words)) {
		return false
	}
	name := commandName(withoutWrapper(words))
	return name == "curl" || name == "wget"
}

// sendsData reports a curl call that sends data or uses a write method: an
// API request whose response it may save, not a file it downloads to use.
func sendsData(words []string) bool {
	if commandName(words) != "curl" {
		return false
	}
	for i, a := range words[1:] {
		switch {
		case a == "-d" || a == "-F" || a == "-T" || a == "--form" || a == "--upload-file" ||
			strings.HasPrefix(a, "--data") || strings.HasPrefix(a, "--json") || strings.HasPrefix(a, "--form="):
			return true
		case (a == "-X" || a == "--request") && i+2 < len(words):
			if m := strings.ToUpper(words[i+2]); m != "GET" && m != "HEAD" {
				return true
			}
		case strings.HasPrefix(a, "-X") && len(a) > 2:
			if m := strings.ToUpper(a[2:]); m != "GET" && m != "HEAD" {
				return true
			}
		}
	}
	return false
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
	if curlStatusProbe(args) {
		return false
	}
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

// curlStatusProbe reports a curl that writes out the HTTP status code
// (-w '%{http_code}'): it checks a service, and the body it saves is at most
// read back on failure, the same as the -o /dev/null probe (#990).
func curlStatusProbe(args []string) bool {
	for i, a := range args {
		v := ""
		switch {
		case (a == "-w" || a == "--write-out") && i+1 < len(args):
			v = args[i+1]
		case strings.HasPrefix(a, "--write-out="):
			v = strings.TrimPrefix(a, "--write-out=")
		case strings.HasPrefix(a, "-w") && len(a) > 2:
			v = a[2:]
		}
		if strings.Contains(v, "%{http_code}") || strings.Contains(v, "%{response_code}") {
			return true
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
