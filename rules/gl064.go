package rules

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl064 struct{}

var GL064 = &gl064{}

func (r *gl064) ID() string { return "GL064" }

//go:embed data/catalog_components.txt
var catalogComponentsData string

// catalogComponents is the baked-in corpus of popular component resource paths
// (namespace/project) used to detect typosquatting.
var catalogComponents = loadCatalogComponents()

func loadCatalogComponents() []string {
	var out []string
	for _, line := range strings.Split(catalogComponentsData, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func (r *gl064) Check(doc *yaml.Node, file string) []finding.Finding {
	mapping := parser.Unwrap(doc)
	includeNode := parser.FindKey(mapping, "include")
	if includeNode == nil || includeNode.Kind != yaml.SequenceNode {
		return nil
	}

	var findings []finding.Finding
	for _, item := range includeNode.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		component := parser.FindKey(item, "component")
		if component == nil || component.Kind != yaml.ScalarNode {
			continue
		}
		resource := componentResourcePath(component.Value)
		if resource == "" {
			continue
		}
		if match, ok := nearestTyposquat(resource); ok {
			findings = append(findings, finding.Finding{
				RuleID:   "GL064",
				Severity: finding.Warn,
				Message: fmt.Sprintf(
					"component path %q is one edit away from the popular component %q under a different namespace — verify it is not a typosquat",
					resource, match,
				),
				File: file,
				Line: component.Line,
				Col:  component.Column,
			})
		}
	}
	return findings
}

// componentResourcePath extracts the catalog resource path (namespace/project)
// from a component include value. It strips the @version, a leading host
// segment, and the trailing component-name segment.
func componentResourcePath(val string) string {
	if at := strings.LastIndex(val, "@"); at >= 0 {
		val = val[:at]
	}
	segs := strings.Split(strings.Trim(val, "/"), "/")
	// Drop a leading host segment (contains a dot, or a $CI_SERVER_* variable).
	if len(segs) > 0 && (strings.Contains(segs[0], ".") || strings.HasPrefix(segs[0], "$")) {
		segs = segs[1:]
	}
	// Drop the trailing component-name segment.
	if len(segs) > 1 {
		segs = segs[:len(segs)-1]
	} else {
		return ""
	}
	if len(segs) < 2 {
		return ""
	}
	return strings.Join(segs, "/")
}

// nearestTyposquat returns a corpus entry that is exactly one edit away from
// resource and sits under a different top-level namespace.
func nearestTyposquat(resource string) (string, bool) {
	resNS := topNamespace(resource)
	for _, c := range catalogComponents {
		if c == resource {
			return "", false // exact match — legitimate
		}
		if topNamespace(c) == resNS {
			continue // same owner — near-misses are not squats
		}
		if editDistanceAtMostOne(resource, c) {
			return c, true
		}
	}
	return "", false
}

func topNamespace(path string) string {
	if i := strings.Index(path, "/"); i >= 0 {
		return path[:i]
	}
	return path
}

// editDistanceAtMostOne reports whether a and b differ by exactly one
// single-character insertion, deletion, or substitution. Equal strings return
// false (distance 0).
func editDistanceAtMostOne(a, b string) bool {
	la, lb := len(a), len(b)
	if la == lb {
		diff := 0
		for i := 0; i < la; i++ {
			if a[i] != b[i] {
				diff++
				if diff > 1 {
					return false
				}
			}
		}
		return diff == 1
	}
	// Lengths differ by one: check for a single insertion/deletion.
	if la > lb {
		a, b = b, a
		la, lb = lb, la
	}
	if lb-la != 1 {
		return false
	}
	i, j := 0, 0
	edited := false
	for i < la && j < lb {
		if a[i] == b[j] {
			i++
			j++
			continue
		}
		if edited {
			return false
		}
		edited = true
		j++ // skip the extra char in the longer string
	}
	return true
}
