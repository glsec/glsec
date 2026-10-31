// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl058 struct{}

var GL058 = &gl058{}

func (r *gl058) ID() string { return "GL058" }

// networkHostRe matches --network host / --net host (space or = separated).
var networkHostRe = regexp.MustCompile(`--net(?:work)?[=\s]+host(?:\s|$)`)

func (r *gl058) Check(doc *yaml.Node, file string) []finding.Finding {
	return dockerRunFlagFindings(doc, file, "GL058", networkHostRe,
		"docker run --network host removes network isolation — the container shares the runner's network stack and can reach localhost services (metadata APIs, internal DBs) and bind any port; use a named network or the default bridge")
}
