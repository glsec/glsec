// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl016 struct {
	trustedHosts []string
}

var GL016 = &gl016{}

func (r *gl016) ID() string { return "GL016" }

// SetTrustedHosts configures the allowlist of hosts/CIDRs that are never flagged.
func (r *gl016) SetTrustedHosts(hosts []string) {
	r.trustedHosts = hosts
}

var (
	gitURLRe       = mustCompilePrefiltered(`\bgit://[^\s'"]+`)
	curlWgetHTTPRe = mustCompilePrefiltered(`\b(?:curl|wget)\b[^|]*\b(?i:http)://`)
	// git fetches remote content just like curl/wget, so the same HTTP check applies.
	gitFetchHTTPRe = mustCompilePrefiltered(`\bgit\b[^|]*\b(?:clone|fetch|pull|remote\s+add|submodule\s+add)\b[^|]*\bhttp://`)
	privateRanges  []*net.IPNet
	internalTLDs   = []string{".local", ".internal", ".corp", ".lan"}
)

func init() {
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		_, network, _ := net.ParseCIDR(cidr)
		privateRanges = append(privateRanges, network)
	}
}

func (r *gl016) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	// include: remote: http://...
	eachIncludeItem(doc, func(item *yaml.Node, job string) {
		if f := r.checkInclude(item, file); f != nil {
			f.Job = job
			findings = append(findings, *f)
		}
	})

	// variables: values, wherever GitLab can apply them
	eachVariablesBlock(doc, func(vars *yaml.Node, job string, _ *yaml.Node) {
		for _, f := range r.checkVariablesHTTP(vars, file) {
			f.Job = job
			findings = append(findings, f)
		}
	})

	// top-level before_script / after_script
	for _, key := range []string{"before_script", "after_script"} {
		if node := parser.FindKey(mapping, key); node != nil {
			findings = append(findings, r.checkScriptHTTP(node, file)...)
		}
	}

	// default: before_script / after_script / hooks
	if def := parser.FindKey(mapping, "default"); def != nil {
		for _, key := range []string{"before_script", "after_script"} {
			if node := parser.FindKey(def, key); node != nil {
				findings = append(findings, r.checkScriptHTTP(node, file)...)
			}
		}
		if h := hookScriptNode(def); h != nil {
			findings = append(findings, r.checkScriptHTTP(h, file)...)
		}
	}

	// A block shared by several jobs through an anchor is checked once; the
	// other jobs' findings would be merged by finding.Dedupe (#766).
	seen := map[*yaml.Node]bool{}
	once := func(n *yaml.Node) bool {
		if n == nil || seen[n] {
			return false
		}
		seen[n] = true
		return true
	}
	// per-job
	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		jobScripts := []*yaml.Node{
			parser.FindKey(job, "script"),
			parser.FindKey(job, "before_script"),
			parser.FindKey(job, "after_script"),
		}
		jobScripts = append(jobScripts, parser.RunStepBlocks(job)...)
		for _, node := range jobScripts {
			if once(node) {
				for _, f := range r.checkScriptHTTP(node, file) {
					f.Job = name.Value
					findings = append(findings, f)
				}
			}
		}
		if h := hookScriptNode(job); once(h) {
			for _, f := range r.checkScriptHTTP(h, file) {
				f.Job = name.Value
				findings = append(findings, f)
			}
		}
	})

	return findings
}

func (r *gl016) checkInclude(item *yaml.Node, file string) *finding.Finding {
	remote := parser.FindKey(item, "remote")
	if remote == nil || remote.Kind != yaml.ScalarNode {
		return nil
	}
	var scheme string
	switch {
	case strings.HasPrefix(remote.Value, "http://"):
		scheme = "HTTP"
	case strings.HasPrefix(remote.Value, "git://"):
		scheme = "the plaintext git:// transport"
	default:
		return nil
	}
	host := hostOf(remote.Value)
	if r.skip(host) {
		return nil
	}
	sev := finding.Error
	msg := "include: remote: uses " + scheme + " — a MITM attacker can inject arbitrary pipeline configuration"
	if isPrivateOrInternal(host) {
		sev = finding.Info
		msg = "include: remote: uses " + scheme + " to a private/internal host — consider HTTPS even on internal networks"
	}
	return &finding.Finding{
		RuleID: "GL016", Severity: sev, Message: msg,
		File: file, Line: remote.Line, Col: remote.Column,
	}
}

func (r *gl016) checkVariablesHTTP(node *yaml.Node, file string) []finding.Finding {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	var findings []finding.Finding
	for i := 0; i+1 < len(node.Content); i += 2 {
		val := node.Content[i+1]
		var scalar *yaml.Node
		switch val.Kind {
		case yaml.ScalarNode:
			scalar = val
		case yaml.MappingNode:
			if v := parser.FindKey(val, "value"); v != nil && v.Kind == yaml.ScalarNode {
				scalar = v
			}
		}
		if scalar == nil {
			continue
		}
		var rawURL, scheme string
		switch {
		case strings.Contains(scalar.Value, "http://"):
			rawURL, scheme = scalar.Value, "HTTP"
		case gitURLRe.MatchString(scalar.Value):
			rawURL, scheme = gitURLRe.FindString(scalar.Value), "the plaintext git:// transport"
		default:
			continue
		}
		host := hostOf(rawURL)
		if r.skip(host) {
			continue
		}
		sev := finding.Info
		msg := "variable value uses " + scheme + " — consider HTTPS to protect data in transit"
		if !isPrivateOrInternal(host) {
			sev = finding.Warn
			msg = "variable value uses " + scheme + " to a public host — a MITM attacker can read or modify traffic"
		}
		findings = append(findings, finding.Finding{
			RuleID: "GL016", Severity: sev, Message: msg,
			File: file, Line: scalar.Line, Col: scalar.Column,
		})
	}
	return findings
}

func (r *gl016) checkScriptHTTP(node *yaml.Node, file string) []finding.Finding {
	if !isScriptList(node) {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		findings = append(findings, r.scriptLineFinding(item, file)...)
	}
	return findings
}

// scriptLineFinding reports every insecure-transport finding for a single
// script scalar: git:// anywhere on the line, otherwise one finding per HTTP
// URL fetched by a known downloader (curl, wget, git) or tool (helm,
// terraform). A `|` block or a `;`-joined line can hold several independent
// downloads of different severities, so each qualifying command is reported,
// not just the first (#1415).
func (r *gl016) scriptLineFinding(item *yaml.Node, file string) []finding.Finding {
	if m := gitURLRe.FindString(item.Value); m != "" {
		host := hostOf(m)
		if !r.skip(host) {
			sev := finding.Warn
			msg := "script fetches over git:// — git's plaintext, unauthenticated transport lets a MITM attacker serve modified source; use https:// or ssh://"
			if isPrivateOrInternal(host) {
				sev = finding.Info
				msg = "script fetches over git:// from a private/internal host — use https:// or ssh://"
			}
			return []finding.Finding{{
				RuleID: "GL016", Severity: sev, Message: msg,
				File: file, Line: item.Line, Col: item.Column,
			}}
		}
	}

	// Each command on its own, and the URL must be one of its words: an
	// http:// URL in a variable or heredoc elsewhere in the block is not what
	// curl or git fetches.
	var findings []finding.Finding
	for _, cmd := range shellCommands(item.Value) {
		var url string
		msgs := downloadHTTPMessages
		switch {
		case curlWgetHTTPRe.MatchString(cmd.text) || gitFetchHTTPRe.MatchString(cmd.text):
			// curl and wget accept the scheme in any case (HTTP://, Http://), so
			// the match ignores case (#827). git refuses an uppercase scheme ("git:
			// 'remote-HTTP' is not a git command"), so gitFetchHTTPRe does not.
			for _, w := range shellWords(cmd.text) {
				if isHTTPURL(w) {
					url = w
					break
				}
			}
			if !cmd.piped && discardsResponse(cmd.text) {
				continue
			}
		default:
			url, msgs = toolHTTPURL(cmd.text)
		}
		if url == "" {
			continue
		}
		host := hostOf(url)
		if r.skip(host) {
			continue
		}
		sev := finding.Warn
		msg := msgs[0]
		if isPrivateOrInternal(host) {
			sev = finding.Info
			msg = msgs[1]
		}
		f := finding.Finding{
			RuleID: "GL016", Severity: sev, Message: msg,
			File: file, Line: parser.ScalarContentLine(item, cmd.line),
		}
		if cmd.line == 0 {
			f.Col = item.Column
		}
		findings = append(findings, f)
	}
	return findings
}

// Each pair is the message for a public host, then for a private/internal one.
var (
	downloadHTTPMessages = [2]string{
		"script downloads over HTTP — a MITM attacker can serve malicious content",
		"script downloads over HTTP from a private/internal host — consider HTTPS",
	}
	helmRepoHTTPMessages = [2]string{
		"helm repo add uses HTTP — a MITM attacker can serve tampered charts (arbitrary Kubernetes manifests and images)",
		"helm repo add uses HTTP to a private/internal host — consider HTTPS",
	}
	terraformBackendHTTPMessages = [2]string{
		"terraform init sends state over HTTP — state often holds secrets a MITM attacker can read or modify",
		"terraform init sends state over HTTP to a private/internal host — consider HTTPS",
	}
)

// containsHTTPFold reports whether s contains "http://" in any case, without
// allocating.
func containsHTTPFold(s string) bool {
	for i := 0; i+len("http://") <= len(s); i++ {
		if isHTTPURL(s[i : i+len("http://")]) {
			return true
		}
	}
	return false
}

func isHTTPURL(w string) bool {
	return len(w) >= len("http://") && strings.EqualFold(w[:len("http://")], "http://")
}

// toolHTTPURL returns the http:// URL a command other than curl, wget or git
// fetches from or sends to, and the messages to report it with: the URL of
// `helm repo add NAME URL`, or an http backend's address passed to `terraform
// init` (or `tofu init`) with -backend-config. Other http:// words, such as
// an API endpoint in a `helm install --set`, are not what these tools fetch.
func toolHTTPURL(text string) (string, [2]string) {
	// Most commands name neither tool: skip them before splitting into words.
	if !strings.Contains(text, "helm") && !strings.Contains(text, "terraform") && !strings.Contains(text, "tofu") ||
		!containsHTTPFold(text) {
		return "", [2]string{}
	}
	words := withoutWrapper(commandWords(text))
	if len(words) == 0 {
		return "", [2]string{}
	}
	args := words[1:]
	switch commandName(words) {
	case "helm":
		for i := 0; i+1 < len(args); i++ {
			if args[i] != "repo" || args[i+1] != "add" {
				continue
			}
			for _, w := range args[i+2:] {
				if isHTTPURL(w) {
					return w, helmRepoHTTPMessages
				}
			}
			break
		}
	case "terraform", "tofu":
		if !slices.Contains(args, "init") {
			break
		}
		for i, a := range args {
			var value string
			switch {
			case a == "-backend-config" || a == "--backend-config":
				if i+1 < len(args) {
					value = args[i+1]
				}
			case strings.HasPrefix(a, "-backend-config="), strings.HasPrefix(a, "--backend-config="):
				_, value, _ = strings.Cut(a, "=")
			}
			// A key=value pair; a value without "=" is a file of settings.
			key, val, ok := strings.Cut(value, "=")
			switch strings.TrimSpace(key) {
			case "address", "lock_address", "unlock_address":
				if val = strings.Trim(strings.TrimSpace(val), `"`); ok && isHTTPURL(val) {
					return val, terraformBackendHTTPMessages
				}
			}
		}
	}
	return "", [2]string{}
}

// devNullStdoutRe matches stdout redirected to /dev/null: > /dev/null,
// 1>/dev/null, &> /dev/null.
var devNullStdoutRe = mustCompilePrefiltered(`(?:^|[^0-9>])(?:1|&)?>>?\s*/dev/null(?:\s|$|;)`)

// discardsResponse reports a curl or wget that checks a URL without keeping
// what it fetches, as a readiness probe does: wget --spider, -o /dev/null,
// HEAD requests, stdout sent to /dev/null (#1279). A status-code probe that
// keeps the body in a file or a variable may still read it.
func discardsResponse(text string) bool {
	words := withoutWrapper(commandWords(text))
	args := words
	if len(args) > 0 {
		args = args[1:]
	}
	switch commandName(words) {
	case "curl":
		for i, a := range args {
			switch {
			case a == "-I" || a == "--head":
				return true
			case (a == "-o" || a == "--output") && i+1 < len(args):
				return args[i+1] == "/dev/null"
			case a == "--output=/dev/null":
				return true
			case a == "-O" || a == "--remote-name":
				return false
			case strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--"):
				// A cluster of short options such as -sSO or -so /dev/null.
				if strings.ContainsRune(a, 'O') {
					return false
				}
				if j := strings.IndexByte(a, 'o'); j > 0 {
					out := a[j+1:]
					if out == "" && i+1 < len(args) {
						out = args[i+1]
					}
					return out == "/dev/null"
				}
			}
		}
		return devNullStdoutRe.MatchString(maskShellQuotes(text))
	case "wget":
		for i, a := range args {
			switch {
			case a == "--spider":
				return true
			case (a == "-O" || a == "--output-document") && i+1 < len(args):
				return args[i+1] == "/dev/null"
			case a == "--output-document=/dev/null":
				return true
			}
		}
	}
	return false
}

// skip returns true if the host should never be flagged (loopback or trusted).
func (r *gl016) skip(host string) bool {
	if isLoopback(host) {
		return true
	}
	for _, entry := range r.trustedHosts {
		if strings.Contains(entry, "/") {
			// CIDR entry
			if hostInCIDR(host, entry) {
				return true
			}
		} else if strings.EqualFold(host, entry) {
			return true
		}
	}
	return false
}

func isLoopback(host string) bool {
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	// RFC 6761: every name under .localhost is loopback.
	if strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func isPrivateOrInternal(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		for _, r := range privateRanges {
			if r.Contains(ip) {
				return true
			}
		}
		return false
	}
	// A name without a dot only resolves inside the job's network: a service
	// container (http://docker:2375, http://postgres:5432) or a compose alias.
	if host != "" && !strings.Contains(host, ".") {
		return true
	}
	lower := strings.ToLower(host)
	for _, tld := range internalTLDs {
		if strings.HasSuffix(lower, tld) {
			return true
		}
	}
	return false
}

func hostInCIDR(host, cidr string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return network.Contains(ip)
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
