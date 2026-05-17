package rules

import (
	"net"
	"net/url"
	"regexp"
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
	httpURLRe     = regexp.MustCompile(`https?://[^\s'"]+`)
	curlWgetHTTPRe = regexp.MustCompile(`\b(?:curl|wget)\b[^|]*\bhttp://`)
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
	findings = append(findings, r.checkIncludes(parser.FindKey(mapping, "include"), file)...)

	// variables: values
	findings = append(findings, r.checkVariablesHTTP(parser.FindKey(mapping, "variables"), file)...)

	// top-level before_script / after_script
	for _, key := range []string{"before_script", "after_script"} {
		if node := parser.FindKey(mapping, key); node != nil {
			findings = append(findings, r.checkScriptHTTP(node, file)...)
		}
	}

	// default: variables / before_script / after_script
	if def := parser.FindKey(mapping, "default"); def != nil {
		findings = append(findings, r.checkVariablesHTTP(parser.FindKey(def, "variables"), file)...)
		for _, key := range []string{"before_script", "after_script"} {
			if node := parser.FindKey(def, key); node != nil {
				findings = append(findings, r.checkScriptHTTP(node, file)...)
			}
		}
	}

	// per-job
	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, f := range r.checkVariablesHTTP(parser.FindKey(job, "variables"), file) {
			f.Job = name.Value
			findings = append(findings, f)
		}
		for _, key := range []string{"script", "before_script", "after_script"} {
			if node := parser.FindKey(job, key); node != nil {
				for _, f := range r.checkScriptHTTP(node, file) {
					f.Job = name.Value
					findings = append(findings, f)
				}
			}
		}
	})

	return findings
}

func (r *gl016) checkIncludes(node *yaml.Node, file string) []finding.Finding {
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		remote := parser.FindKey(item, "remote")
		if remote == nil || remote.Kind != yaml.ScalarNode {
			continue
		}
		if !strings.HasPrefix(remote.Value, "http://") {
			continue
		}
		host := hostOf(remote.Value)
		if r.skip(host) {
			continue
		}
		sev := finding.Error
		msg := "include: remote: uses HTTP — a MITM attacker can inject arbitrary pipeline configuration"
		if isPrivateOrInternal(host) {
			sev = finding.Info
			msg = "include: remote: uses HTTP to a private/internal host — consider HTTPS even on internal networks"
		}
		findings = append(findings, finding.Finding{
			RuleID: "GL016", Severity: sev, Message: msg,
			File: file, Line: remote.Line, Col: remote.Column,
		})
	}
	return findings
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
		if scalar == nil || !strings.Contains(scalar.Value, "http://") {
			continue
		}
		host := hostOf(scalar.Value)
		if r.skip(host) {
			continue
		}
		sev := finding.Info
		msg := "variable value uses HTTP — consider HTTPS to protect data in transit"
		if !isPrivateOrInternal(host) {
			sev = finding.Warn
			msg = "variable value uses HTTP to a public host — a MITM attacker can read or modify traffic"
		}
		findings = append(findings, finding.Finding{
			RuleID: "GL016", Severity: sev, Message: msg,
			File: file, Line: scalar.Line, Col: scalar.Column,
		})
	}
	return findings
}

func (r *gl016) checkScriptHTTP(node *yaml.Node, file string) []finding.Finding {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		if !curlWgetHTTPRe.MatchString(item.Value) {
			continue
		}
		// Extract the http:// URL from the line to get the host.
		m := httpURLRe.FindString(item.Value)
		if m == "" || !strings.HasPrefix(m, "http://") {
			continue
		}
		host := hostOf(m)
		if r.skip(host) {
			continue
		}
		sev := finding.Warn
		msg := "script downloads over HTTP — a MITM attacker can serve malicious content"
		if isPrivateOrInternal(host) {
			sev = finding.Info
			msg = "script downloads over HTTP from a private/internal host — consider HTTPS"
		}
		findings = append(findings, finding.Finding{
			RuleID: "GL016", Severity: sev, Message: msg,
			File: file, Line: item.Line, Col: item.Column,
		})
	}
	return findings
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
