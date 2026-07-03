package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl076 struct{}

var GL076 = &gl076{}

func (r *gl076) ID() string { return "GL076" }

// unconfinedRe captures a --security-opt flag that disables the seccomp or
// AppArmor profile (space or = separated between flag and value).
var unconfinedRe = regexp.MustCompile(`--security-opt[=\s]+(seccomp|apparmor)=unconfined`)

func (r *gl076) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		v := line.Value
		if strings.HasPrefix(strings.TrimSpace(v), "#") {
			return
		}
		if !dockerRunRe.MatchString(v) {
			return
		}
		for _, m := range unconfinedRe.FindAllStringSubmatch(v, -1) {
			profile := strings.ToLower(m[1])
			findings = append(findings, finding.Finding{
				RuleID:   "GL076",
				Severity: finding.Warn,
				Job:      job,
				Message: fmt.Sprintf(
					"docker run --security-opt %s=unconfined disables the container's %s confinement, removing kernel-level syscall/behavior restrictions — this widens the container-escape surface without needing --privileged; keep the default profile or supply a scoped custom one",
					profile, profile,
				),
				File: file,
				Line: line.Line,
				Col:  line.Column,
			})
		}
	})
	return findings
}
