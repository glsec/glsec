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

type gl060 struct{}

var GL060 = &gl060{}

func (r *gl060) ID() string { return "GL060" }

// volumeFlagRe captures the volume spec passed to -v / --volume.
var volumeFlagRe = regexp.MustCompile(`(?:^|\s)(?:--volume|-v)[=\s]+(\S+)`)

// mountFlagRe captures the mount spec passed to --mount (space or equals form).
var mountFlagRe = regexp.MustCompile(`(?:^|\s)--mount[=\s]+(\S+)`)

// containerRunRe matches run and create commands of the container engines
// whose bind mounts this rule covers. It is local to GL060 so the wider
// dockerRunRe, shared with other rules, keeps its existing meaning.
var containerRunRe = regexp.MustCompile(`\b(?:docker|podman|nerdctl)\s+(?:container\s+)?(?:run|create)\b`)

// errorMountPaths are host source paths whose exposure is critical.
var errorMountPaths = []string{"/etc", "/root", "/proc", "/sys"}

// warnMountPaths are host source paths that are sensitive but lower-impact.
// /run sits next to /var/run because on current distributions /var/run is a
// symlink to /run, so a mount of either spells the same runtime directory.
var warnMountPaths = []string{"/var/run", "/run", "/dev", "/boot"}

func (r *gl060) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		v := line.Value
		if strings.HasPrefix(strings.TrimSpace(v), "#") {
			return
		}
		if !containerRunRe.MatchString(v) {
			return
		}
		for _, m := range volumeFlagRe.FindAllStringSubmatchIndex(v, -1) {
			spec := strings.Trim(v[m[2]:m[3]], `"'`)
			findings = append(findings, mountFinding(volumeSource(spec), volumeReadOnly(spec), file, job, line, m[0])...)
		}
		for _, m := range mountFlagRe.FindAllStringSubmatchIndex(v, -1) {
			spec := v[m[2]:m[3]]
			src, ok := mountBindSource(spec)
			if !ok {
				continue
			}
			findings = append(findings, mountFinding(src, mountReadOnly(spec), file, job, line, m[0])...)
		}
	})
	return findings
}

// mountFinding returns one finding for a host source path, or none when the
// path is not sensitive. This rule owns bind mounts in scripts, including
// socket mounts, so a socket mount yields this one finding; GL055 covers
// DOCKER_HOST references only.
func mountFinding(src string, readOnly bool, file, job string, line *yaml.Node, off int) []finding.Finding {
	sev, ok := hostMountSeverity(src)
	if !ok {
		return nil
	}
	// World-readable identity files mounted read-only, to map the runner's
	// user into the container, expose nothing the job can't read (#995).
	if readOnly && readOnlyIdentityFiles[strings.TrimSuffix(src, "/")] {
		return nil
	}
	access := "read/write"
	if readOnly {
		access = "read"
	}
	ln, col := scriptMatchPos(line, off)
	return []finding.Finding{{
		RuleID:   "GL060",
		Severity: sev,
		Job:      job,
		Message: fmt.Sprintf(
			"container run mounts sensitive host path %q — breaks container isolation; the job can %s host files outside the container. Mount only $CI_PROJECT_DIR or a named volume",
			src, access,
		),
		File: file, Line: ln, Col: col,
	}}
}

// mountBindSource returns the host source of a --mount spec, but only for a
// bind mount: a named volume (type=volume) or a tmpfs mount is not a host
// path exposure. The target (target= or dst=) is ignored; only the source
// side matters, as with -v.
func mountBindSource(spec string) (string, bool) {
	spec = strings.Trim(spec, `"'`)
	var typ, src string
	for _, kv := range strings.Split(spec, ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch k {
		case "type":
			typ = v
		case "source", "src":
			src = v
		}
	}
	if typ != "bind" || src == "" {
		return "", false
	}
	return src, true
}

// readOnlyIdentityFiles are world-readable host files containers commonly
// get read-only to see the runner's users or time zone.
var readOnlyIdentityFiles = map[string]bool{
	"/etc/passwd": true, "/etc/group": true, "/etc/localtime": true, "/etc/timezone": true,
}

// volumeReadOnly reports whether a -v spec SRC:DST:opts mounts read-only.
func volumeReadOnly(spec string) bool {
	parts := strings.Split(spec, ":")
	if len(parts) < 3 {
		return false
	}
	for _, o := range strings.Split(parts[len(parts)-1], ",") {
		if o == "ro" || o == "readonly" {
			return true
		}
	}
	return false
}

// mountReadOnly reports whether a --mount spec has readonly (or ro).
func mountReadOnly(spec string) bool {
	for _, kv := range strings.Split(strings.Trim(spec, `"'`), ",") {
		k, v, _ := strings.Cut(kv, "=")
		if (k == "readonly" || k == "ro") && v != "false" && v != "0" {
			return true
		}
	}
	return false
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
