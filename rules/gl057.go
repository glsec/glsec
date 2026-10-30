// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl057 struct{}

var GL057 = &gl057{}

func (r *gl057) ID() string { return "GL057" }

// capAddRe captures the capability passed to a --cap-add flag (space or =
// separated). The value may carry a CAP_ prefix and any case.
var capAddRe = regexp.MustCompile(`--cap-add[=\s]+([A-Za-z_]+)`)

// dangerousCaps are individual Linux capabilities that meaningfully expand the
// container's ability to affect the host. Granting any of these is flagged.
var dangerousCaps = map[string]bool{
	"SYS_ADMIN":  true,
	"SYS_PTRACE": true,
	"SYS_MODULE": true,
	"NET_ADMIN":  true,
}

func (r *gl057) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		v := line.Value
		if strings.HasPrefix(strings.TrimSpace(v), "#") {
			return
		}
		if !dockerRunRe.MatchString(v) {
			return
		}
		for _, m := range capAddRe.FindAllStringSubmatchIndex(v, -1) {
			cap := strings.ToUpper(strings.TrimPrefix(strings.ToUpper(v[m[2]:m[3]]), "CAP_"))
			ln, col := scriptMatchPos(line, m[0])
			switch {
			case cap == "ALL":
				findings = append(findings, finding.Finding{
					RuleID:   "GL057",
					Severity: finding.Error,
					Job:      job,
					Message:  "docker run --cap-add ALL grants every Linux capability — equivalent to --privileged; grant only the specific capability required",
					File:     file, Line: ln, Col: col,
				})
			case dangerousCaps[cap]:
				findings = append(findings, finding.Finding{
					RuleID:   "GL057",
					Severity: finding.Warn,
					Job:      job,
					Message: fmt.Sprintf(
						"docker run --cap-add %s grants a dangerous capability that can be abused to escape the container or affect the runner host — grant only the minimal capability required",
						cap,
					),
					File: file, Line: ln, Col: col,
				})
			}
		}
	})
	return findings
}
