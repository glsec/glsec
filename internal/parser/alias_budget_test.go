package parser

import (
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// One anchored subtree that is by itself larger than the whole budget: its
// alias must stay an alias rather than be expanded in place.
func TestAliasExpansion_OversizedAnchor(t *testing.T) {
	var src strings.Builder
	src.WriteString("big: &big\n")
	for i := 0; i < maxExpandedNodes+10; i++ {
		src.WriteString("  - x\n")
	}
	src.WriteString("job:\n  script: *big\n")

	start := time.Now()
	doc, err := Parse([]byte(src.String()), "test.yml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("parsing took %v", d)
	}

	script := FindKey(FindKey(doc.MappingNode(), "job"), "script")
	if script == nil || script.Kind != yaml.AliasNode {
		t.Fatalf("an alias to an over-budget anchor should be left unexpanded, got kind %v", script.Kind)
	}
}
