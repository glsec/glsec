// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"net"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl097 struct{}

// GL097 flags a script step that references a secret-like variable and, in the
// same connected pipeline, sends data off the runner to a destination no
// pipeline legitimately publishes to: a public bare-IPv4 URL, or a known
// request/webhook catcher, tunnel or OAST host. That is the shape of credential
// exfiltration from a poisoned pipeline (e.g. the GhostAction campaign, 2026:
// planted `curl` to a raw IP with named secrets).
//
// The naive "a secret and an egress verb in the same step" check is not
// shippable — on real pipelines it fires on ~every publish (a release job
// POSTing a token to its own service has the same shape). What separates
// publishing from exfiltration is where the data goes, so GL097 gates on the
// destination: a secret sent to a named service domain the project could own is
// publishing and is not flagged. Forwarding the GitLab job token to any
// non-GitLab host is GL004's (warn) concern; GL097 adds any secret to an
// untrusted drop point at error. Both may fire on the narrow overlap.
var GL097 = &gl097{}

func (r *gl097) ID() string { return "GL097" }

var (
	// gl097SecretRef matches a shell reference to a secret-like variable:
	// $NAME / ${NAME} whose name carries TOKEN, SECRET, PASSWORD, PASSWD,
	// CREDENTIAL, APIKEY or API_KEY, or ends a segment with _KEY (so
	// AWS_SECRET_ACCESS_KEY and SSH_KEY match, MONKEY does not). Names are
	// matched upper case, the CI/CD variable convention.
	gl097SecretRef = mustCompilePrefiltered(`\$\{?[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|APIKEY|API_KEY|_KEY)[A-Z0-9_]*\}?`)

	// gl097DropPointRe matches a host that exists to receive data a pipeline
	// should not send: request/webhook catchers, tunnels, and OAST/interaction
	// services. None is a service a project publishes releases to. Matched on
	// the host itself (own domain or any subdomain), case-insensitively.
	gl097DropPointRe = mustCompilePrefiltered(`(?i)(?:^|\.)(?:webhook\.site|requestbin\.(?:com|net)|requestcatcher\.com|pipedream\.net|ngrok\.io|ngrok-free\.app|trycloudflare\.com|loca\.lt|serveo\.net|interact\.sh|oast\.(?:pro|live|site|fun|me)|burpcollaborator\.net|beeceptor\.com)$`)

	gl097CGNAT *net.IPNet
)

func init() {
	_, gl097CGNAT, _ = net.ParseCIDR("100.64.0.0/10")
}

// gl097Egress are the commands that send data off the runner.
var gl097Egress = map[string]bool{
	"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true,
}

func (r *gl097) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		v := line.Value
		// Cheap prefilter: a variable reference and an egress verb must both be
		// present before the shell parse runs.
		if !strings.Contains(v, "$") || !gl097HasEgress(v) {
			return
		}
		if strings.HasPrefix(strings.TrimSpace(v), "#") {
			return
		}
		cmds := shellCommands(v)
		// Walk each connected pipeline (a run joined by `|`). Commands separated
		// by ;, && or || run independently: a secret in one and an egress in
		// another are not paired.
		for i := 0; i < len(cmds); {
			j := i
			for j < len(cmds)-1 && cmds[j].piped {
				j++
			}
			if dest, cmdLine := gl097PipeExfil(cmds[i : j+1]); dest != "" {
				f := finding.Finding{
					RuleID:   "GL097",
					Severity: finding.Error,
					Job:      job,
					Message: fmt.Sprintf(
						"secret-like variable sent to untrusted destination %q — a pipeline publishes with its credentials to services it owns; a bare public IP, tunnel or request-catcher is not one. Treat the secret as exposed, rotate it, and review who added this step",
						dest),
					File: file,
					Line: parser.ScalarContentLine(line, cmdLine),
				}
				if cmdLine == 0 {
					f.Col = line.Column
				}
				findings = append(findings, f)
				return
			}
			i = j + 1
		}
	})
	return findings
}

func gl097HasEgress(v string) bool {
	return strings.Contains(v, "curl") || strings.Contains(v, "wget") ||
		strings.Contains(v, "nc")
}

// gl097PipeExfil reports the untrusted destination a connected pipeline sends a
// secret to, and the item line of the egress command, or "" when the pipeline
// carries no secret or every destination is one a project could own.
func gl097PipeExfil(pipe []shellCommand) (string, int) {
	hasSecret := false
	for _, c := range pipe {
		if gl097SecretRef.MatchString(c.text) {
			hasSecret = true
			break
		}
	}
	if !hasSecret {
		return "", 0
	}
	for _, c := range pipe {
		words := commandWords(c.text)
		if len(words) == 0 {
			continue
		}
		name := commandName(words)
		if !gl097Egress[name] {
			continue
		}
		if dest := gl097UntrustedDest(name, words); dest != "" {
			return dest, c.line
		}
	}
	return "", 0
}

// gl097UntrustedDest returns the untrusted destination a command sends to, or ""
// when every destination is one a project could legitimately own. For curl and
// wget it is the host of a URL argument; for nc it is the host operand.
func gl097UntrustedDest(name string, words []string) string {
	for _, w := range words[1:] {
		w = strings.Trim(w, `"'`)
		if h := urlHost(w); h != "" {
			if gl097Untrusted(h) {
				return h
			}
			continue
		}
		if name == "nc" || name == "ncat" || name == "netcat" {
			if w == "" || strings.HasPrefix(w, "-") {
				continue
			}
			if gl097Untrusted(strings.ToLower(w)) {
				return w
			}
		}
	}
	return ""
}

func gl097Untrusted(host string) bool {
	return gl097PublicIP(host) || gl097DropPointRe.MatchString(host)
}

// gl097PublicIP reports whether host is an IP literal that is globally routable:
// not loopback, private (RFC1918 / ULA), link-local, CGNAT, multicast or
// unspecified. An internal registry or artifact server reached by a private IP
// is deliberately not flagged.
func gl097PublicIP(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if gl097CGNAT != nil && gl097CGNAT.Contains(ip) {
		return false
	}
	return true
}
