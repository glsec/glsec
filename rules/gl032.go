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

type gl032 struct{}

var GL032 = &gl032{}

func (r *gl032) ID() string { return "GL032" }

var (
	// keyVarRe matches a variable reference whose name implies key material
	// (contains PRIVATE or a _KEY segment). Group 1 is the variable name.
	keyVarRe = regexp.MustCompile(`\$\{?([A-Za-z0-9_]*(?:PRIVATE|_KEY)[A-Za-z0-9_]*)\}?`)

	// substEchoRe matches echo/printf inside a process or command substitution;
	// group 1 is what it prints.
	substEchoRe = regexp.MustCompile(`(?:<\(|\$\()\s*(?:echo|printf)\b([^)]*)`)

	// sshRedirectRe matches a pipeline's output redirected into a file under an
	// .ssh/ directory; group 1 is the target filename.
	sshRedirectRe = regexp.MustCompile(`>.*\.ssh/([A-Za-z0-9._-]*)`)
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
	EachScriptBlock(doc, file, func(node *yaml.Node, file, job string) {
		findings = append(findings, checkSSHKeyEcho(node, file, job)...)
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
		for _, line := range sshKeyEchoLines(item.Value) {
			f := finding.Finding{
				RuleID:   "GL032",
				Severity: finding.Warn,
				Job:      job,
				Message:  "private key written via echo — its value appears in the job log when debug tracing (set -x / CI_DEBUG_TRACE) is active; use a file-type variable or a here-string instead, e.g. ssh-add - <<< \"$KEY\"",
				File:     file,
				Line:     parser.ScalarContentLine(item, line),
			}
			if line == 0 {
				f.Col = item.Column
			}
			findings = append(findings, f)
		}
	}
	return findings
}

// sshKeyEchoLines returns the item lines of pipelines that echo/print private
// key material: a key-named variable printed by echo/printf, or echo output
// written into a key file under .ssh/. Public and host keys, writes into
// non-key .ssh/ files and *.pub files don't count. Each pipeline is looked at
// on its own, so an echo and a key-named variable in different commands of a
// block are not combined.
func sshKeyEchoLines(script string) []int {
	var lines []int
	cmds := shellCommands(script)
	for i := 0; i < len(cmds); i++ {
		first := cmds[i]
		pipeline := []string{first.text}
		for cmds[i].piped && i+1 < len(cmds) {
			i++
			pipeline = append(pipeline, cmds[i].text)
		}
		name := commandName(withoutSudo(commandWords(first.text)))
		if name != "echo" && name != "printf" {
			// echo inside a substitution: ssh-add <(echo "$KEY"), $(echo …).
			if m := substEchoRe.FindStringSubmatch(maskSingleQuoted(first.text)); m != nil {
				if private, _ := printedKeyVars(m[1]); private {
					lines = append(lines, first.line)
				}
			}
			continue
		}
		private, public := printedKeyVars(maskSingleQuoted(first.text))
		joined := strings.Join(pipeline, " | ")
		m := sshRedirectRe.FindStringSubmatch(joined)
		keyFile := m != nil && !sshNonKeyTargets[m[1]] && !strings.HasSuffix(m[1], ".pub")
		// Only a key that is written counts: piped into a command or
		// redirected to a file. An echo that only prints a key-named
		// variable, often a cache key, writes nothing; printing a secret is
		// GL021's (#993).
		written := len(pipeline) > 1 || strings.Contains(maskSingleQuoted(joined), ">")
		if !written {
			if at := strings.Index(script, first.text); at >= 0 {
				written = groupOutputDiverted(script, at) // { …; echo "$KEY"; } | gpg --import
			}
		}
		// A write into a key file counts when it carries a variable: printf
		// '\n' >> ~/.ssh/id_ed25519 writes no key material.
		expands := strings.Contains(maskSingleQuoted(first.text), "$")
		if private && written || keyFile && !public && expands {
			lines = append(lines, first.line)
		}
	}
	return lines
}

// printedKeyVars reports whether a print command outputs key-named variables:
// private ones, and clearly public ones (PUBLIC, HOST or a _PUB segment in
// the name).
func printedKeyVars(cmd string) (private, public bool) {
	for _, m := range keyVarRe.FindAllStringSubmatch(cmd, -1) {
		name := strings.ToUpper(m[1])
		if strings.Contains(name, "PUBLIC") || strings.Contains(name, "HOST") || strings.HasSuffix(name, "_PUB") || strings.Contains(name, "_PUB_") {
			public = true
		} else {
			private = true
		}
	}
	return private, public
}
