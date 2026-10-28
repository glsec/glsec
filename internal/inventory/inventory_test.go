// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

var update = flag.Bool("update", false, "rewrite the testdata golden files")

func collect(t *testing.T, src string) map[string]Item {
	t.Helper()
	doc, err := parser.Parse([]byte(src), ".gitlab-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]Item{}
	for _, it := range Collect(doc) {
		out[string(it.Kind)+" "+it.Ref+" "+it.Version] = it
	}
	return out
}

func TestCollect_Pinning(t *testing.T) {
	got := collect(t, `
include:
  - component: gitlab.com/g/p/c@1.2.3
  - component: gitlab.com/g/p/c@1
  - component: gitlab.com/g/p/c@~latest
  - component: gitlab.com/g/p/nover
  - component: gitlab.com/g/p/c@0123456789abcdef0123456789abcdef01234567
  - component: $[[ inputs.c ]]@1.0.0
  - project: g/t
    ref: v2.0.0
    file: a.yml
  - project: g/t
    ref: master
    file: b.yml
  - project: g/u
    file: c.yml
  - remote: https://example.com/a.yml
job:
  image: node:20.11.0
  services: [postgres:17, "mysql:8.4.3", redis]
  script: [x]
`)
	want := map[string]Pinning{
		"component gitlab.com/g/p/c@1.2.3 1.2.3":     PinVersion,
		"component gitlab.com/g/p/c@1 1":             PinMutable,
		"component gitlab.com/g/p/c@~latest ~latest": PinMutable,
		"component gitlab.com/g/p/nover ":            PinNone,
		"component gitlab.com/g/p/c@0123456789abcdef0123456789abcdef01234567 0123456789abcdef0123456789abcdef01234567": PinSHA,
		"component $[[ inputs.c ]]@1.0.0 1.0.0": PinUnresolved,
		"project g/t v2.0.0":                    PinVersion,
		"project g/t master":                    PinMutable,
		"project g/u ":                          PinNone,
		"remote https://example.com/a.yml ":     PinNone,
		"image node:20.11.0 20.11.0":            PinVersion,
		"service postgres:17 17":                PinMutable,
		"service mysql:8.4.3 8.4.3":             PinVersion,
		"service redis ":                        PinNone,
	}
	for key, pin := range want {
		it, ok := got[key]
		if !ok {
			t.Errorf("missing %q", key)
			continue
		}
		if it.Pinning != pin {
			t.Errorf("%q: pinning %q, want %q", key, it.Pinning, pin)
		}
	}
	if len(got) != len(want) {
		t.Errorf("%d items, want %d: %v", len(got), len(want), got)
	}
}

func TestCollect_Inheritance(t *testing.T) {
	got := collect(t, `
image: busybox:1.37.0
default:
  services: [postgres:17.2]
.base:
  image: node:22.11.0
a:
  extends: .base
  script: [x]
b:
  script: [x]
.hidden:
  image: never:1.0.0
  script: [x]
`)
	if it := got["image node:22.11.0 22.11.0"]; strings.Join(it.Jobs, ",") != "a" {
		t.Errorf("extends: image jobs = %v", it.Jobs)
	}
	if it := got["image busybox:1.37.0 1.37.0"]; strings.Join(it.Jobs, ",") != "b" {
		t.Errorf("top-level image jobs = %v", it.Jobs)
	}
	if it := got["service postgres:17.2 17.2"]; strings.Join(it.Jobs, ",") != "a,b" {
		t.Errorf("default: services jobs = %v", it.Jobs)
	}
	if _, ok := got["image never:1.0.0 1.0.0"]; ok {
		t.Error("image of a hidden job listed")
	}
}

func TestDockerPURL(t *testing.T) {
	for _, c := range []struct{ name, version, want string }{
		{"node", "20.11.0", "pkg:docker/library/node@20.11.0"},
		{"bitnami/kubectl", "1.31.2", "pkg:docker/bitnami/kubectl@1.31.2"},
		{"docker.io/library/alpine", "3.22.2", "pkg:docker/library/alpine@3.22.2"},
		{"ghcr.io/glsec/glsec", "1.24.1", "pkg:docker/glsec/glsec@1.24.1?repository_url=ghcr.io"},
		{"localhost:5000/team/App", "sha256:ab", "pkg:docker/team/app@sha256%3Aab?repository_url=localhost:5000"},
		{"alpine", "", "pkg:docker/library/alpine"},
	} {
		if got := dockerPURL(c.name, c.version); got != c.want {
			t.Errorf("dockerPURL(%q, %q) = %q, want %q", c.name, c.version, got, c.want)
		}
	}
}

// TestWriteCycloneDX compares the BOM of testdata/pipeline.yml with
// testdata/pipeline.cdx.json, which CI validates against the CycloneDX 1.6
// schema. After an intended change: go test ./internal/inventory -update
func TestWriteCycloneDX(t *testing.T) {
	doc, err := parser.ParseFile(filepath.Join("testdata", "pipeline.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteCycloneDX(&buf, ".gitlab-ci.yml", "1.2.3", Collect(doc)); err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "pipeline.cdx.json")
	if *update {
		if err := os.WriteFile(golden, buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden) //nolint:gosec // G304: the package's own golden file
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if got := buf.String(); got != strings.ReplaceAll(string(want), "\r\n", "\n") {
		t.Errorf("BOM differs from %s (run with -update after an intended change)\ngot:\n%s", golden, got)
	}

	var again bytes.Buffer
	_ = WriteCycloneDX(&again, ".gitlab-ci.yml", "1.2.3", Collect(doc))
	if again.String() != buf.String() {
		t.Error("BOM not deterministic")
	}
}

func TestWriteCycloneDX_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCycloneDX(&buf, "x.yml", "", nil); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"components": []`, `"dependsOn": []`, `"version": "dev"`, `"serialNumber": "urn:uuid:`} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("empty BOM lacks %s:\n%s", want, buf.String())
		}
	}
}

func TestCollect_EdgeCases(t *testing.T) {
	got := collect(t, `
include:
  - project: g/t
    ref: v1.0.0
    file: a.yml
  - project: g/t
    ref: v1.0.0
    file: [a.yml, b.yml]
  - project: [not, a, string]
  - component: [not, a, string]
  - remote: [not, a, string]
  - remote: https://$HOST/ci.yml
  - template: $TEMPLATE
  - template: [x]
a:
  image: {entrypoint: [""]}
  services: [{alias: x}, ""]
  script: [x]
b:
  image: ""
  script: [x]
c:
  image: node:22.11.0
  script: [x]
d:
  image: node:22.11.0
  script: [x]
`)
	if it := got["project g/t v1.0.0"]; strings.Join(it.Files, ",") != "a.yml,b.yml" {
		t.Errorf("merged project files = %v", it.Files)
	}
	if got["remote https://$HOST/ci.yml "].Pinning != PinUnresolved || got["template $TEMPLATE "].Pinning != PinUnresolved {
		t.Errorf("variables not unresolved: %v", got)
	}
	if it := got["image node:22.11.0 22.11.0"]; strings.Join(it.Jobs, ",") != "c,d" {
		t.Errorf("image used by two jobs: %v", it.Jobs)
	}
	if len(got) != 4 {
		t.Errorf("%d items, want 4 (project, remote, template, image): %v", len(got), got)
	}
}
