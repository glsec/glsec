// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func TestGL001_TagOrDigestFromVariable(t *testing.T) {
	for _, tc := range []struct {
		image string
		want  int
	}{
		{"${ECR_REGISTRY}/docker-hub/alpine/kubectl@${KUBECTL_CI_SHA}", 0},
		{"${DEPENDENCY_PROXY_PREFIX}${BASE_QA_IMAGE}", 0},
		{"$REGISTRY_MIRROR/$BUILD_BASE_IMAGE", 0},
		{"$TMP_IMAGE$IMAGE_TAG_SUFFIX", 0},
		{"registry.example.com/esp32-ci-env$BOT_DOCKER_IMAGE_TAG", 0},
		{"${CI_REGISTRY_IMAGE}/builder", 1},
		{"alpine", 1},
	} {
		doc, err := parser.Parse([]byte("job:\n  image: \""+tc.image+"\"\n  script: [x]\n"), "t.yml")
		if err != nil {
			t.Fatal(err)
		}
		if f := GL001.Check(doc.Root, "t.yml"); len(f) != tc.want {
			t.Errorf("%s: expected %d findings, got %d", tc.image, tc.want, len(f))
		}
	}
}

func TestGL016_ServiceHostsAndLocalhost(t *testing.T) {
	for _, tc := range []struct {
		value string
		sev   finding.Severity // "" means no finding
	}{
		{"http://docker:50052", finding.Info},
		{"http://backend:8000", finding.Info},
		{"http://selenium:4444/wd/hub", finding.Info},
		{"http://app.exosphere.localhost:8000", ""},
		{"http://downloads.example.org/x", finding.Warn},
	} {
		doc, err := parser.Parse([]byte("job:\n  variables:\n    URL: \""+tc.value+"\"\n  script: [x]\n"), "t.yml")
		if err != nil {
			t.Fatal(err)
		}
		f := GL016.Check(doc.Root, "t.yml")
		switch {
		case tc.sev == "" && len(f) != 0:
			t.Errorf("%s: expected no finding, got %v", tc.value, f)
		case tc.sev != "" && (len(f) != 1 || f[0].Severity != tc.sev):
			t.Errorf("%s: expected one %s finding, got %v", tc.value, tc.sev, f)
		}
	}
}
