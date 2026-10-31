// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl077 struct{}

var GL077 = &gl077{}

func (r *gl077) ID() string { return "GL077" }

// ipcHostRe matches --ipc host / --ipc=host.
var ipcHostRe = regexp.MustCompile(`--ipc[=\s]+host(?:\s|$)`)

func (r *gl077) Check(doc *yaml.Node, file string) []finding.Finding {
	return dockerRunFlagFindings(doc, file, "GL077", ipcHostRe,
		"docker run --ipc host shares the host IPC namespace — the container can read the host's shared memory and POSIX message queues and signal host processes; omit --ipc or scope it with --ipc container:<id>")
}
