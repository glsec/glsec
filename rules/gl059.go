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

type gl059 struct{}

var GL059 = &gl059{}

func (r *gl059) ID() string { return "GL059" }

var (
	dockerBuildRe = regexp.MustCompile(`\bdocker\s+(?:buildx\s+)?build\b`)
	buildArgRe    = regexp.MustCompile(`--build-arg[=\s]+([A-Za-z_][A-Za-z0-9_]*)`)
	// secretArgNameRe matches a secret keyword as an underscore- or
	// boundary-delimited token, so NPM_TOKEN / API_KEY / DB_PASSWORD match but
	// BYPASS_CACHE / VERSION / MONKEY do not.
	secretArgNameRe = regexp.MustCompile(`(^|_)(TOKEN|SECRET|PASSWORD|PASS|KEY|CREDENTIAL|AUTH)(_|$)`)
)

func (r *gl059) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		v := line.Value
		if strings.HasPrefix(strings.TrimSpace(v), "#") {
			return
		}
		if !dockerBuildRe.MatchString(v) {
			return
		}
		for _, m := range buildArgRe.FindAllStringSubmatchIndex(v, -1) {
			name := v[m[2]:m[3]]
			upper := strings.ToUpper(name)
			if !secretArgNameRe.MatchString(upper) || nonSecretSuffixRe.MatchString(upper) {
				continue
			}
			ln, col := scriptMatchPos(line, m[0])
			findings = append(findings, finding.Finding{
				RuleID:   "GL059",
				Severity: finding.Warn,
				Job:      job,
				Message: fmt.Sprintf(
					"docker build --build-arg %s embeds a secret into image layer metadata (visible via `docker history --no-trunc`) — use BuildKit secret mounts (--secret id=...) instead",
					name,
				),
				File: file, Line: ln, Col: col,
			})
		}
	})
	return findings
}
