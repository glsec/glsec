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

type gl069 struct{}

var GL069 = &gl069{}

func (r *gl069) ID() string { return "GL069" }

type pkgAuthCheck struct {
	re  *regexp.Regexp
	msg string
	// keep, if set, decides whether a match of re counts.
	keep func(match string) bool
}

// shellCommandRe is the rest of a shell command after its name, across
// backslash-continued lines.
const shellCommandRe = `\b(?:\\\n|[^\n;&|])*`

// remoteWithFlag returns a keep function for a whole package-manager command:
// it has flag, and it doesn't only install local files.
func remoteWithFlag(flag string) func(string) bool {
	return func(command string) bool {
		return strings.Contains(command, flag) && !installsLocalFilesOnly(command)
	}
}

// installsLocalFilesOnly reports a package-manager command that takes its
// packages from local files, as in dnf localinstall ./build/x.rpm: a package
// the job built is signed by no one, so there is no signature to skip.
func installsLocalFilesOnly(command string) bool {
	words := shellWords(strings.ReplaceAll(command, "\\\n", " "))
	var args []string
	for _, w := range words {
		switch {
		case w == "localinstall" || w == "localupdate" || w == "--no-remote":
			return true
		case !strings.HasPrefix(w, "-"):
			args = append(args, w)
		}
	}
	if len(args) < 3 { // the manager, its subcommand and a package
		return false
	}
	for _, w := range args[2:] {
		if strings.Contains(w, "://") || !strings.HasSuffix(strings.ToLower(w), ".rpm") && !strings.HasPrefix(w, "./") {
			return false
		}
	}
	return true
}

// pkgAuthChecks match package-manager invocations that turn off signature /
// authentication verification (a different control from TLS verification, which
// GL042 covers). Each is a high-signal, explicit bypass flag.
var pkgAuthChecks = []pkgAuthCheck{
	{
		// Scoped to an apt command on the same line: "--allow-unauthenticated"
		// is also a GCP Cloud Run flag (gcloud run deploy --allow-unauthenticated)
		// meaning public service access, which is unrelated to package signatures.
		re:  regexp.MustCompile(`\b(?:apt-get|apt|aptitude)\b[^\n]*--allow-unauthenticated\b`),
		msg: `apt "--allow-unauthenticated" disables package signature verification — an unsigned or tampered package from a compromised or MITM'd mirror would install without error; import the repository signing key and reference it with signed-by= instead`,
	},
	{
		re:  regexp.MustCompile(`(?i)allowunauthenticated"?\s*=\s*"?(?:true|1|yes)\b`),
		msg: `apt option "APT::Get::AllowUnauthenticated=true" disables package signature verification — unsigned packages install without error; keep verification on and trust the repository via its signing key (signed-by=) instead`,
	},
	{
		re:  regexp.MustCompile(`(?i)\[[^][]*\btrusted\s*=\s*(?:yes|true|1)\b[^][]*\]`),
		msg: `apt source marked "[trusted=yes]" disables package signature verification for that repository — use "signed-by=<keyring>" to verify packages against the repository's GPG key instead`,
	},
	{
		re:  regexp.MustCompile(`\b(?:apt-get|apt|aptitude)\b[^\n]*--allow-insecure-repositories\b`),
		msg: `apt "--allow-insecure-repositories" lets apt use repositories without a valid signature — a compromised or MITM'd mirror can serve any package; import the repository signing key and reference it with signed-by= instead`,
	},
	{
		re:  regexp.MustCompile(`(?i)\bAllowInsecureRepositories"?\s*=?\s*"?(?:true|1|yes)\b`),
		msg: `apt option "Acquire::AllowInsecureRepositories" lets apt use repositories without a valid signature — a compromised or MITM'd mirror can serve any package; import the repository signing key and reference it with signed-by= instead`,
	},
	{
		// dnf5, yum, microdnf and tdnf share dnf's flag.
		re:   regexp.MustCompile(`\b(?:dnf5?|yum|microdnf|tdnf)` + shellCommandRe),
		keep: remoteWithFlag("--nogpgcheck"),
		msg:  `"--nogpgcheck" installs packages without checking their GPG signatures, for every repository in the command — a tampered package from a compromised or MITM'd mirror installs without error; import the repository's key with rpm --import instead`,
	},
	{
		// repo_gpgcheck and localpkg_gpgcheck are other settings. The literal
		// \n is echo -e's line break in a repo file written on one line.
		re:  regexp.MustCompile(`(?im)(?:^|[^a-z0-9_]|\\n)gpgcheck\s*=\s*(?:0|false|no)\b`),
		msg: `"gpgcheck=0" turns off GPG signature checks for the repository — every later install from it is unverified; set gpgcheck=1 and point gpgkey= at the repository's key instead`,
	},
	{
		re:   regexp.MustCompile(`\bzypper` + shellCommandRe),
		keep: remoteWithFlag("--no-gpg-checks"),
		msg:  `zypper "--no-gpg-checks" installs packages without checking their GPG signatures — a tampered package from a compromised or MITM'd mirror installs without error; import the repository's key with rpm --import instead`,
	},
	{
		// RemoteFileSigLevel covers packages pacman -U fetches from a URL.
		re:  regexp.MustCompile(`\b(?:RemoteFile)?SigLevel\s*=\s*Never\b`),
		msg: `pacman "SigLevel = Never" turns off signature checks for packages and databases — a tampered package from a compromised or MITM'd mirror installs without error; keep the default and add the key with pacman-key instead`,
	},
	{
		re:  regexp.MustCompile(`\bapk\b[^\n]*--allow-untrusted\b`),
		msg: `apk "--allow-untrusted" disables package signature verification — an unsigned or tampered package would install without error; add the repository's signing key to /etc/apk/keys instead`,
	},
	{
		re:  regexp.MustCompile(`\bGOSUMDB=(?:"off"|'off'|off)(?:\s|$)`),
		msg: `GOSUMDB=off disables the Go checksum database — modules are fetched without being verified against sum.golang.org, so a tampered dependency installs silently; keep the default and scope private modules with GOPRIVATE/GONOSUMDB instead`,
	},
	{
		// A specific host such as GONOSUMDB=gitlab.example.com/* is the normal
		// private-module setup, so only a bare wildcard is a bypass.
		re:  regexp.MustCompile(`\b(?:GONOSUMDB|GOINSECURE)=(?:"\*"|'\*'|\*)(?:\s|$)`),
		msg: `GONOSUMDB=* or GOINSECURE=* disables module checksum or TLS verification for every host, not just the private ones it was meant for — list your own module hosts instead of a wildcard`,
	},
}

// goModuleVerificationOff maps the Go settings that switch off module
// verification to the value that does it. A specific host such as
// GONOSUMDB=gitlab.example.com/* is the normal private-module setup and must
// stay quiet, so only "off" and a bare "*" count.
var goModuleVerificationOff = map[string]string{
	"GOSUMDB":    "off",
	"GONOSUMDB":  "*",
	"GOINSECURE": "*",
}

func goModuleVerificationMessage(name string) string {
	if name == "GOSUMDB" {
		return `GOSUMDB=off disables the Go checksum database — modules are fetched without being verified against sum.golang.org, so a tampered dependency installs silently; keep the default and scope private modules with GOPRIVATE/GONOSUMDB instead`
	}
	return `GONOSUMDB=* or GOINSECURE=* disables module checksum or TLS verification for every host, not just the private ones it was meant for — list your own module hosts instead of a wildcard`
}

// checkGoModuleVariables reports Go verification switched off through a
// variables block, which EachScriptLine does not reach.
func checkGoModuleVariables(node *yaml.Node, file, job string) []finding.Finding {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	var findings []finding.Finding
	for i := 0; i+1 < len(node.Content); i += 2 {
		off, ok := goModuleVerificationOff[node.Content[i].Value]
		if !ok {
			continue
		}
		value := node.Content[i+1]
		if value.Kind == yaml.MappingNode {
			value = parser.FindKey(value, "value")
		}
		if value == nil || value.Kind != yaml.ScalarNode || value.Value != off {
			continue
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL069",
			Severity: finding.Warn,
			Job:      job,
			Message:  goModuleVerificationMessage(node.Content[i].Value),
			File:     file,
			Line:     value.Line,
			Col:      value.Column,
		})
	}
	return findings
}

func (r *gl069) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	eachVariablesBlock(doc, func(vars *yaml.Node, job string, _ *yaml.Node) {
		findings = append(findings, checkGoModuleVariables(vars, file, job)...)
	})

	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		if strings.HasPrefix(strings.TrimSpace(line.Value), "#") {
			return
		}
		for _, c := range pkgAuthChecks {
			loc := c.find(line.Value)
			if loc == nil {
				continue
			}
			ln, col := scriptMatchPos(line, loc[0])
			findings = append(findings, finding.Finding{
				RuleID:   "GL069",
				Severity: finding.Warn,
				Job:      job,
				Message:  c.msg,
				File:     file,
				Line:     ln,
				Col:      col,
			})
			break
		}
	})
	return findings
}

// find returns the first match in script that counts. A match on a comment
// line of a block doesn't.
func (c pkgAuthCheck) find(script string) []int {
	for _, loc := range c.re.FindAllStringIndex(script, -1) {
		start := strings.LastIndexByte(script[:loc[0]], '\n') + 1
		if strings.HasPrefix(strings.TrimSpace(script[start:loc[0]]), "#") {
			continue
		}
		if c.keep == nil || c.keep(script[loc[0]:loc[1]]) {
			return loc
		}
	}
	return nil
}
