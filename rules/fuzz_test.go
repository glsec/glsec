// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

// FuzzRules runs every rule over arbitrary parsed input. The opt-in allowlist
// rules get a list, so their matching code runs too.
func FuzzRules(f *testing.F) {
	paths, err := filepath.Glob(filepath.Join("..", "testdata", "fixtures", "*.yml"))
	if err != nil {
		f.Fatal(err)
	}
	for _, p := range paths {
		data, err := os.ReadFile(p) //nolint:gosec // G304: test reads the repository's own fixtures
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	GL065.SetAllowedRegistries([]string{"registry.example.com", "docker.io/library"})
	GL075.SetAllowedIncludeSources([]string{"my-group", "gitlab.com/components", "$CI_SERVER_FQDN/ci"})
	f.Cleanup(func() {
		GL065.SetAllowedRegistries(nil)
		GL075.SetAllowedIncludeSources(nil)
	})
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := parser.Parse(data, "fuzz.yml")
		if err != nil {
			return
		}
		for _, r := range All() {
			Check(r, doc, "fuzz.yml")
		}
	})
}
