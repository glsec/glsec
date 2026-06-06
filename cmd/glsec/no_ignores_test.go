package main

import (
	"os"
	"testing"

	"github.com/glsec/glsec/internal/config"
	"github.com/glsec/glsec/internal/parser"
	"github.com/glsec/glsec/internal/suppress"
	gitlabver "github.com/glsec/glsec/internal/version"
)

// node:latest triggers GL001; the inline directive suppresses it on that line.
const inlineIgnoreYAML = "build:\n  image: node:latest  # glsec:ignore GL001 -- updated monthly\n  script: [echo hi]\n"

func hasGL001(t *testing.T, content string, skipSuppress bool) bool {
	t.Helper()
	doc, err := parser.Parse([]byte(content), "test.yml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, f := range collectFindings(doc, "test.yml", config.Default(), gitlabver.Version{}, skipSuppress, false) {
		if f.RuleID == "GL001" {
			return true
		}
	}
	return false
}

func TestCollectFindings_InlineIgnoreSuppresses(t *testing.T) {
	if hasGL001(t, inlineIgnoreYAML, false) {
		t.Fatal("expected GL001 suppressed by inline directive, but it was reported")
	}
}

func TestCollectFindings_NoIgnoresBypassesInline(t *testing.T) {
	if !hasGL001(t, inlineIgnoreYAML, true) {
		t.Fatal("expected GL001 reported with --no-ignores, but it was suppressed")
	}
}

// plainYAML has no inline directive; GL001 fires on line 2 (the image).
const plainYAML = "build:\n  image: node:latest\n  script: [echo hi]\n"

func TestCollectFindings_NoIgnoresBypassesBaseline(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile(suppress.IgnoreFile, []byte("test.yml:2 GL001\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if hasGL001(t, plainYAML, false) {
		t.Fatal("expected GL001 suppressed by .glsec-ignore baseline, but it was reported")
	}
	if !hasGL001(t, plainYAML, true) {
		t.Fatal("expected GL001 reported with --no-ignores despite baseline, but it was suppressed")
	}
}
