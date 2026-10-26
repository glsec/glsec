// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

// A script block merged into many jobs through an anchor is scanned once, not
// once per job (#766).
func TestSharedScriptBlockScannedOnce(t *testing.T) {
	var b strings.Builder
	b.WriteString(".tpl: &tpl\n  script:\n    - |\n")
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&b, "      curl -sSL https://example.com/%d -o f%d && echo done %d\n", i, i, i)
	}
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&b, "job%d:\n  <<: *tpl\n", i)
	}
	doc, err := parser.Parse([]byte(b.String()), "t.yml")
	if err != nil {
		t.Fatal(err)
	}
	visits := 0
	EachScriptBlock(doc.Root, "t.yml", func(*yaml.Node, string, string) { visits++ })
	if visits != 1 {
		t.Fatalf("shared block visited %d times, want 1", visits)
	}
	perJob := 0
	EachScriptBlockPerJob(doc.Root, "t.yml", func(*yaml.Node, string, string) { perJob++ })
	if perJob != 501 {
		t.Fatalf("per-job visits = %d, want 501", perJob)
	}
	start := time.Now()
	for _, r := range All() {
		r.Check(doc.Root, "t.yml")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("all rules took %v on the shared-anchor file", d)
	}
}
