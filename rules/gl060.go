package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl060 struct{}

var GL060 = &gl060{}

func (r *gl060) ID() string { return "GL060" }

// volumeFlagRe captures the volume spec passed to -v / --volume.
var volumeFlagRe = regexp.MustCompile(`(?:^|\s)(?:--volume|-v)[=\s]+(\S+)`)

// errorMountPaths are host source paths whose exposure is critical.
var errorMountPaths = []string{"/etc", "/root", "/proc", "/sys"}

// warnMountPaths are host source paths that are sensitive but lower-impact.
var warnMountPaths = []string{"/var/run", "/dev", "/boot"}

func (r *gl060) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		v := line.Value
		if strings.HasPrefix(strings.TrimSpace(v), "#") {
			return
		}
		if !dockerRunRe.MatchString(v) {
			return
		}
		for _, m := range volumeFlagRe.FindAllStringSubmatch(v, -1) {
			src := volumeSource(m[1])
			sev, ok := hostMountSeverity(src)
			if !ok {
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "GL060",
				Severity: sev,
				Job:      job,
				Message: fmt.Sprintf(
					"docker run mounts sensitive host path %q — breaks container isolation; the job can read/write host files outside the container. Mount only $CI_PROJECT_DIR or a named volume",
					src,
				),
				File: file, Line: line.Line, Col: line.Column,
			})
		}
	})
	return findings
}

// volumeSource returns the host (source) side of a bind-mount spec SRC:DST[:opts].
func volumeSource(spec string) string {
	if i := strings.Index(spec, ":"); i >= 0 {
		return spec[:i]
	}
	return spec
}

func hostMountSeverity(src string) (finding.Severity, bool) {
	if src == "/" {
		return finding.Error, true
	}
	if !strings.HasPrefix(src, "/") {
		return "", false // named volume or relative path
	}
	src = strings.TrimSuffix(src, "/")
	for _, p := range errorMountPaths {
		if src == p || strings.HasPrefix(src, p+"/") {
			return finding.Error, true
		}
	}
	for _, p := range warnMountPaths {
		if src == p || strings.HasPrefix(src, p+"/") {
			return finding.Warn, true
		}
	}
	return "", false
}
