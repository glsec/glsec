// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl061 struct{}

var GL061 = &gl061{}

func (r *gl061) ID() string { return "GL061" }

// pidHostRe matches --pid host / --pid=host.
var pidHostRe = regexp.MustCompile(`--pid[=\s]+host(?:\s|$)`)

func (r *gl061) Check(doc *yaml.Node, file string) []finding.Finding {
	return dockerRunFlagFindings(doc, file, "GL061", pidHostRe,
		"docker run --pid host shares the host PID namespace — the container can see, signal, and read memory of all host processes (other jobs, the runner agent); omit --pid or scope it with --pid container:<id>")
}
