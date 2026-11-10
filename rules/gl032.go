// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"slices"
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
	keyVarRe = mustCompilePrefiltered(`\$\{?([A-Za-z0-9_]*(?:PRIVATE|_KEY)[A-Za-z0-9_]*)\}?`)

	// substEchoRe matches echo/printf inside a process or command substitution;
	// group 1 is what it prints.
	substEchoRe = mustCompilePrefiltered(`(?:<\(|\$\()\s*(?:echo|printf)\b([^)]*)`)

	// sshRedirectRe matches a pipeline's output redirected into a file under an
	// .ssh/ directory; group 1 is the target filename.
	sshRedirectRe = mustCompilePrefiltered(`>.*\.ssh/([A-Za-z0-9._-]*)`)
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
		for _, echo := range sshKeyEchoLines(item.Value) {
			msg := "private key written via echo — its value appears in the job log when debug tracing (set -x / CI_DEBUG_TRACE) is active; use a file-type variable or a here-string instead, e.g. ssh-add - <<< \"$KEY\""
			if echo.credential {
				msg = "key credential (passphrase/keystore password) written via echo — its value appears in the job log when debug tracing (set -x / CI_DEBUG_TRACE) is active; use a masked or file-type variable instead"
			}
			f := finding.Finding{
				RuleID:   "GL032",
				Severity: finding.Warn,
				Job:      job,
				Message:  msg,
				File:     file,
				Line:     parser.ScalarContentLine(item, echo.line),
			}
			if echo.line == 0 {
				f.Col = item.Column
			}
			findings = append(findings, f)
		}
	}
	return findings
}

// keyEcho locates a flagged echo/printf and records whether the leaked value
// is a key credential (passphrase/keystore password) rather than key material,
// so the finding can word it accurately.
type keyEcho struct {
	line       int
	credential bool
}

// sshKeyEchoLines returns the pipelines that echo/print private key material or
// a key credential: a key-named variable printed by echo/printf, or echo output
// written into a key file under .ssh/. Public and host keys, key aliases,
// writes into non-key .ssh/ files and *.pub files don't count. Each pipeline is
// looked at on its own, so an echo and a key-named variable in different
// commands of a block are not combined.
func sshKeyEchoLines(script string) []keyEcho {
	var echoes []keyEcho
	cmds := shellCommands(script)
	for i := 0; i < len(cmds); i++ {
		first := cmds[i]
		pipeline := []string{first.text}
		for cmds[i].piped && i+1 < len(cmds) {
			i++
			pipeline = append(pipeline, cmds[i].text)
		}
		name := commandName(commandWords(first.text))
		if name != "echo" && name != "printf" {
			// echo inside a substitution: ssh-add <(echo "$KEY"), $(echo …).
			if m := substEchoRe.FindStringSubmatch(maskSingleQuoted(first.text)); m != nil {
				if private, credential, _ := printedKeyVars(m[1]); (private || credential) && tracedFromParent(first) {
					echoes = append(echoes, keyEcho{first.line, !private && credential})
				}
			}
			continue
		}
		private, credential, public := printedKeyVars(maskSingleQuoted(first.text))
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
		keyFileWrite := keyFile && !public && expands
		if ((private || credential) && written || keyFileWrite) && tracedFromParent(first) {
			// A key-file write and a key-material variable are key material; a
			// passphrase/password with no key material gets credential wording.
			material := private || keyFileWrite
			echoes = append(echoes, keyEcho{first.line, !material && credential})
		}
	}
	// A double-quoted sh -c script is seen twice, in the parent and as its
	// own commands; one finding per line is enough.
	return slices.Compact(echoes)
}

var xtraceOnRe = mustCompilePrefiltered(`\bset\s+(?:-[a-zA-Z]*x|-o\s+xtrace)`)

// tracedFromParent reports whether debug tracing can show a command's key. A
// command from a sh -c script runs in a child shell that doesn't inherit the
// runner's set -o xtrace, so only what the parent expands reaches the trace:
// in bash -c 'echo "$KEY"' the single quotes keep $KEY literal (#1283),
// unless the script turns tracing on itself.
func tracedFromParent(cmd shellCommand) bool {
	if cmd.parent == "" {
		return true
	}
	private, credential, _ := printedKeyVars(maskSingleQuoted(cmd.parent))
	return private || credential || xtraceOnRe.MatchString(cmd.parent)
}

// printedKeyVars classifies the key-named variables a print command outputs:
// key material (private), a key credential such as a passphrase or keystore
// password (credential), and clearly non-secret names — public keys, host keys
// and key aliases (public). An alias names a key, it isn't one, so it is not a
// secret; a passphrase or keystore password is a secret but not a private key,
// so it gets its own wording (#1107).
func printedKeyVars(cmd string) (private, credential, public bool) {
	for _, m := range keyVarRe.FindAllStringSubmatch(cmd, -1) {
		name := strings.ToUpper(m[1])
		switch {
		case strings.Contains(name, "PUBLIC") || strings.Contains(name, "HOST") ||
			strings.HasSuffix(name, "_PUB") || strings.Contains(name, "_PUB_") ||
			strings.Contains(name, "ALIAS"):
			public = true
		case strings.Contains(name, "PASSWORD") || strings.Contains(name, "PASSWD") ||
			strings.Contains(name, "PASSPHRASE"):
			credential = true
		default:
			private = true
		}
	}
	return private, credential, public
}
