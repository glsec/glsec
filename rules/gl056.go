package rules

import (
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl056 struct{}

var GL056 = &gl056{}

func (r *gl056) ID() string { return "GL056" }

var (
	dockerRunRe          = regexp.MustCompile(`\bdocker\s+(?:container\s+)?run\b`)
	privilegedFlagRe     = regexp.MustCompile(`--privileged\b`)
	privilegedDisabledRe = regexp.MustCompile(`--privileged=(?:false|0)\b`)
)

func (r *gl056) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		v := line.Value
		if strings.HasPrefix(strings.TrimSpace(v), "#") {
			return
		}
		if !dockerRunRe.MatchString(v) {
			return
		}
		if !privilegedFlagRe.MatchString(v) || privilegedDisabledRe.MatchString(v) {
			return
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL056",
			Severity: finding.Warn,
			Job:      job,
			Message:  "docker run --privileged grants the container full host kernel access (all capabilities, unrestricted devices) — use --cap-add for the specific capabilities needed, or a rootless tool like Podman/Buildah",
			File:     file,
			Line:     line.Line,
			Col:      line.Column,
		})
	})
	return findings
}
