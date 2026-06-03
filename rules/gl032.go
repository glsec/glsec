package rules

import (
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl032 struct{}

var GL032 = &gl032{}

func (r *gl032) ID() string { return "GL032" }

var (
	// echoPrintfRe matches a shell print command.
	echoPrintfRe = regexp.MustCompile(`\b(?:echo|printf)\b`)

	// keyVarRe matches a variable reference whose name implies key material
	// (contains PRIVATE or a _KEY segment). Group 1 is the variable name.
	keyVarRe = regexp.MustCompile(`\$\{?([A-Za-z0-9_]*(?:PRIVATE|_KEY)[A-Za-z0-9_]*)\}?`)

	// sshRedirectRe matches echoing/printing redirected or piped into a file
	// under an .ssh/ directory; group 1 is the target filename.
	sshRedirectRe = regexp.MustCompile(`\b(?:echo|printf)\b.*[|>].*\.ssh/([A-Za-z0-9._-]*)`)
)

// sshNonKeyTargets are .ssh/ files that hold configuration or public keys, not
// private key material, so echoing into them is not a leaked private key.
var sshNonKeyTargets = map[string]bool{
	"config":          true,
	"known_hosts":     true,
	"authorized_keys": true,
}

func (r *gl032) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	for _, key := range []string{"before_script", "after_script"} {
		if node := parser.FindKey(mapping, key); node != nil {
			findings = append(findings, checkSSHKeyEcho(node, file, "")...)
		}
	}
	if def := parser.FindKey(mapping, "default"); def != nil {
		for _, key := range []string{"before_script", "after_script"} {
			if node := parser.FindKey(def, key); node != nil {
				findings = append(findings, checkSSHKeyEcho(node, file, "")...)
			}
		}
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, key := range []string{"script", "before_script", "after_script"} {
			if node := parser.FindKey(job, key); node != nil {
				findings = append(findings, checkSSHKeyEcho(node, file, name.Value)...)
			}
		}
	})

	return findings
}

func checkSSHKeyEcho(node *yaml.Node, file, job string) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		if sshKeyEchoLine(item.Value) {
			findings = append(findings, finding.Finding{
				RuleID:   "GL032",
				Severity: finding.Warn,
				Job:      job,
				Message:  "private key written via echo — its value appears in the job log when debug tracing (set -x / CI_DEBUG_TRACE) is active; feed it through stdin instead, e.g. echo \"$KEY\" | ssh-add -",
				File:     file,
				Line:     item.Line,
				Col:      item.Column,
			})
		}
	}
	return findings
}

// sshKeyEchoLine reports whether a script line echoes/prints private key
// material. It excludes public/host keys and writes into non-key .ssh/ files
// (config, known_hosts, authorized_keys).
func sshKeyEchoLine(line string) bool {
	// Destination-based: echo redirected/piped into an .ssh/ key file.
	if m := sshRedirectRe.FindStringSubmatch(line); m != nil && !sshNonKeyTargets[m[1]] {
		return true
	}
	// Variable-name based: a private-key-named variable being printed.
	return echoesPrivateKey(line)
}

// echoesPrivateKey reports whether a print command outputs a variable whose
// name implies a private key, ignoring clearly-public ones (PUBLIC, HOST keys).
func echoesPrivateKey(line string) bool {
	loc := echoPrintfRe.FindStringIndex(line)
	if loc == nil {
		return false
	}
	for _, m := range keyVarRe.FindAllStringSubmatch(line[loc[1]:], -1) {
		name := strings.ToUpper(m[1])
		if strings.Contains(name, "PUBLIC") || strings.Contains(name, "HOST") {
			continue
		}
		return true
	}
	return false
}
