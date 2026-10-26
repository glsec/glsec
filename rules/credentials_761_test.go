// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strconv"
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

func TestDockerHubTokenPattern(t *testing.T) {
	tok := "dckr_pat_" + "Zq8Lr3Nw5Tb7Vx9Kc2Hj4Mp6Rs1"
	doc, err := parser.Parse([]byte("variables:\n  CI_REGISTRY_PASSWORD: \""+tok+"\"\njob:\n  script:\n    - docker login -u me --password-stdin <<< "+tok+"\n"), "t.yml")
	if err != nil {
		t.Fatal(err)
	}
	if f := GL006.Check(doc.Root, "t.yml"); len(f) != 1 {
		t.Errorf("GL006: expected 1 finding, got %d", len(f))
	}
	if f := GL088.Check(doc.Root, "t.yml"); len(f) != 1 {
		t.Errorf("GL088: expected 1 finding, got %d", len(f))
	}
}

func TestDockerLoginPasswords(t *testing.T) {
	for _, tc := range []struct {
		script       string
		gl038, gl029 int
	}{
		{"docker login -u deploy -p s3cretpass registry.example.com", 1, 1},
		{"docker login --username=deploy --password s3cretpass registry.example.com", 1, 1},
		{"podman login -u deploy --password='s3cretpass' registry.example.com", 1, 1},
		{`docker login -u "$CI_REGISTRY_USER" -p "$CI_REGISTRY_PASSWORD" $CI_REGISTRY`, 0, 1},
		{"docker login -u $U --password $P $CI_REGISTRY", 0, 1},
		{`echo "$CI_REGISTRY_PASSWORD" | docker login -u "$CI_REGISTRY_USER" --password-stdin $CI_REGISTRY`, 0, 0},
		{"docker login -u x -p -", 0, 1},
		{`ssh host "docker login -u \\${U} -p \\${P} reg"`, 0, 1},
	} {
		doc, err := parser.Parse([]byte("job:\n  script:\n    - "+strconv.Quote(tc.script)+"\n"), "t.yml")
		if err != nil {
			t.Fatal(err)
		}
		if f := GL038.Check(doc.Root, "t.yml"); len(f) != tc.gl038 {
			t.Errorf("GL038 %s: expected %d, got %d", tc.script, tc.gl038, len(f))
		}
		if f := GL029.Check(doc.Root, "t.yml"); len(f) != tc.gl029 {
			t.Errorf("GL029 %s: expected %d, got %d", tc.script, tc.gl029, len(f))
		}
	}
}
