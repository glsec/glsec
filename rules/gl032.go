package rules

import (
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl032 struct{}

var GL032 = &gl032{}

func (r *gl032) ID() string { return "GL032" }

var (
	// sshKeyVarRe matches echoing/printing a variable whose name implies a
	// private key (contains PRIVATE or a _KEY suffix), to any destination.
	sshKeyVarRe = regexp.MustCompile(
		`\b(?:echo|printf)\b.*\$(?:\{[A-Za-z_]*(?:PRIVATE|_KEY)[A-Za-z_]*\}|[A-Za-z_]*(?:PRIVATE|_KEY)[A-Za-z_]*)`)

	// sshRedirectRe matches echoing/printing redirected or piped into a file
	// under an .ssh/ directory; the captured group is the target filename.
	sshRedirectRe = regexp.MustCompile(
		`\b(?:echo|printf)\b.*[|>].*\.ssh/([A-Za-z0-9._-]*)`)
)

// sshNonKeyTargets are .ssh/ files that hold configuration, not key material,
// so echoing into them is not a leaked private key (e.g. appending
// "StrictHostKeyChecking no" to ~/.ssh/config).
var sshNonKeyTargets = map[string]bool{
	"config":      true,
	"known_hosts": true,
}

// sshKeyEchoLine reports whether a script line echoes/prints a private key.
func sshKeyEchoLine(line string) bool {
	if sshKeyVarRe.MatchString(line) {
		return true
	}
	if m := sshRedirectRe.FindStringSubmatch(line); m != nil {
		return !sshNonKeyTargets[m[1]]
	}
	return false
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
				Message:  "SSH private key written to file via echo — key value appears in job logs when debug tracing is active; use ssh-add with stdin instead: echo \"$KEY\" | ssh-add -",
				File:     file,
				Line:     item.Line,
				Col:      item.Column,
			})
		}
	}
	return findings
}
