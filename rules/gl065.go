package rules

import (
	"fmt"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl065 struct {
	allowedRegistries []string
}

var GL065 = &gl065{}

func (r *gl065) ID() string { return "GL065" }

// SetAllowedRegistries configures the opt-in registry allowlist. When empty,
// the rule is a no-op and flags nothing (avoids flagging every docker.io image
// by default).
func (r *gl065) SetAllowedRegistries(registries []string) {
	r.allowedRegistries = registries
}

func (r *gl065) Check(doc *yaml.Node, file string) []finding.Finding {
	if len(r.allowedRegistries) == 0 {
		return nil
	}

	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	findings = append(findings, r.checkImage(parser.FindKey(mapping, "image"), file)...)
	findings = append(findings, r.checkServices(parser.FindKey(mapping, "services"), file)...)

	if def := parser.FindKey(mapping, "default"); def != nil {
		findings = append(findings, r.checkImage(parser.FindKey(def, "image"), file)...)
		findings = append(findings, r.checkServices(parser.FindKey(def, "services"), file)...)
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, f := range r.checkImage(parser.FindKey(job, "image"), file) {
			f.Job = name.Value
			findings = append(findings, f)
		}
		for _, f := range r.checkServices(parser.FindKey(job, "services"), file) {
			f.Job = name.Value
			findings = append(findings, f)
		}
	})

	return findings
}

func (r *gl065) checkImage(node *yaml.Node, file string) []finding.Finding {
	if node == nil {
		return nil
	}
	ref, line, col := imageRef(node)
	return r.checkRegistry(ref, line, col, file)
}

func (r *gl065) checkServices(node *yaml.Node, file string) []finding.Finding {
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		ref, line, col := imageRef(item)
		findings = append(findings, r.checkRegistry(ref, line, col, file)...)
	}
	return findings
}

func (r *gl065) checkRegistry(ref string, line, col int, file string) []finding.Finding {
	if ref == "" {
		return nil
	}
	// The registry host of $REGISTRY/app or a fully variable ref ($MY_IMAGE) is
	// not statically resolvable, so it cannot be checked against the allowlist.
	if registryHostUnresolvable(ref) {
		return nil
	}
	host, normalized := normalizeRegistry(ref)
	if registryAllowed(host, normalized, r.allowedRegistries) {
		return nil
	}
	return []finding.Finding{{
		RuleID:   "GL065",
		Severity: finding.Warn,
		Message:  fmt.Sprintf("image %q is from registry %q, which is not in the allowed_registries allowlist", ref, host),
		File:     file, Line: line, Col: col,
	}}
}

// registryHostUnresolvable reports whether the registry-host portion of an
// image reference contains a variable expansion.
func registryHostUnresolvable(ref string) bool {
	first := ref
	if i := strings.Index(ref, "/"); i >= 0 {
		first = ref[:i]
	}
	return strings.Contains(first, "$")
}

// normalizeRegistry returns the registry host and the reference normalized to
// carry an explicit, lowercased host. The first path segment is the registry
// only when it contains a "." or ":port" (or is "localhost"); bare images
// (node:20) and Docker Hub namespaces (myorg/app) resolve to docker.io.
func normalizeRegistry(ref string) (host, normalized string) {
	if i := strings.Index(ref, "/"); i >= 0 {
		first := ref[:i]
		if first == "localhost" || strings.ContainsAny(first, ".:") {
			host = strings.ToLower(first)
			return host, host + ref[i:]
		}
	}
	return "docker.io", "docker.io/" + ref
}

// registryAllowed reports whether the image matches any allowlist entry. A bare
// entry (registry.example.com) matches by host; an entry that contains a path
// (ghcr.io/myorg) matches as a host/namespace prefix of the normalized ref.
func registryAllowed(host, normalized string, allow []string) bool {
	normLower := strings.ToLower(normalized)
	for _, entry := range allow {
		e := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(entry), "/"))
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			if normLower == e || strings.HasPrefix(normLower, e+"/") {
				return true
			}
		} else if host == e {
			return true
		}
	}
	return false
}
