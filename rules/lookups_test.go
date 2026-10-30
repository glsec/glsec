// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"
)

// TokenPatterns finds GL006's tokens inside longer text, for the report
// redaction (#831), and leaves out the markers that aren't tokens.
func TestTokenPatterns(t *testing.T) {
	patterns := TokenPatterns()
	if len(patterns) != len(secretPatterns)-2 {
		t.Errorf("got %d patterns, want all of GL006's but the PEM and GCP markers (%d)", len(patterns), len(secretPatterns)-2)
	}
	for _, p := range patterns {
		if strings.HasPrefix(p.String(), "^") || strings.HasSuffix(p.String(), "$") {
			t.Errorf("%s is still anchored", p)
		}
	}
	token := "gl" + "pat-" + strings.Repeat("aB3x", 5)
	nuget := "OY2" + "A" + strings.Repeat("A", 15) + "A" + strings.Repeat("A", 25) + "A"
	for _, text := range []string{
		"push failed for token " + token + " (expired)",
		"key " + nuget + " rejected", // a (?i) pattern keeps its flag
	} {
		found := false
		for _, p := range patterns {
			if p.MatchString(text) {
				found = true
			}
		}
		if !found {
			t.Errorf("no pattern finds the token in %q", text)
		}
	}
	for _, p := range patterns {
		if p.MatchString("-----BEGIN RSA PRIVATE KEY-----") || p.MatchString(`"type": "service_account"`) {
			t.Errorf("%s matches a key marker", p)
		}
	}
}

func TestTaxonomyLookups(t *testing.T) {
	if got := ASVSRequirements("GL011"); len(got) == 0 {
		t.Error("GL011 has no ASVS requirement")
	}
	for _, id := range ASVSRequirements("GL011") {
		if ASVSRequirementName(id) == "" {
			t.Errorf("%s has no name", id)
		}
	}
	if ASVSRequirementName("ASVS-V0.0.0") != "" {
		t.Error("an unknown ASVS requirement has a name")
	}
	for _, cat := range OWASPCategories("GL001") {
		if OWASPCategoryName(cat) == "" {
			t.Errorf("%s has no name", cat)
		}
	}
	if OWASPCategoryName("CICD-SEC-99") != "" {
		t.Error("an unknown OWASP category has a name")
	}
}

// A variable whose value is neither a string nor a {value: …} mapping holds
// no secret value to check.
func TestGL006_NonScalarVariableValue(t *testing.T) {
	f := findings006(t, "variables:\n  LIST:\n    - "+"gl"+"pat-"+strings.Repeat("aB3x", 5)+"\n  EMPTY:\n    description: no value\nbuild:\n  script: [echo ok]\n")
	if len(f) != 0 {
		t.Errorf("got %v, want no finding", f)
	}
}
