// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl005 struct{}

var GL005 = &gl005{}

func (r *gl005) ID() string { return "GL005" }

// sensitivePatterns are glob patterns matching files that commonly contain secrets.
var sensitivePatterns = []string{
	".env", ".env.*",
	"*.pem", "*.key", "*.p12", "*.pfx", "*.der",
	"*.keystore", "*.jks",
	"id_rsa", "id_ecdsa", "id_ed25519", "id_dsa",
	"*.secret", "*secret*",
	"*credential*", "*credentials*",
	"*password*", "*passwd*",
	"*.token",
	"kubeconfig", "*.kubeconfig",
	"*.tfstate", "*.tfvars",
	// Package manager and registry config files that hold auth tokens:
	// npm/Yarn, PyPI uploads, netrc logins, and docker login (#1133).
	".npmrc", ".yarnrc.yml", ".pypirc",
	".netrc", "_netrc",
	".dockercfg",
}

// sensitivePathPatterns are files whose base name alone is too common to
// flag (a bare config.json is usually an app config), so the parent
// directory is part of the match.
var sensitivePathPatterns = []string{
	".docker/config.json",
}

// gitlabReportArtifacts are GitLab's own Secret Detection artifacts: the
// findings report (uploaded via artifacts:reports:secret_detection) and the
// scanner's ruleset bundle. They hold findings about secrets, not secrets
// themselves, so the "*secret*" match on their names is a false positive
// (#1101).
var gitlabReportArtifacts = []string{
	"gl-secret-detection-report.json",
	"secret-detection-rules.zip",
}

func (r *gl005) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)
	in := NewInheritance(doc)

	if def := parser.FindKey(mapping, "default"); def != nil {
		if artifactsNode := parser.FindKey(def, "artifacts"); artifactsNode != nil {
			findings = append(findings, checkArtifactPaths(doc, nil, artifactsNode, file, nil)...)
			if _, e := parser.FindKeyNode(artifactsNode, "expire_in"); e == nil {
				findings = append(findings, missingExpireIn(artifactsNode, file))
			}
		}
	}

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		// Paths are checked where they are written, templates included.
		if own := parser.FindKey(job, "artifacts"); own != nil {
			for _, f := range checkArtifactPaths(doc, in, own, file, unredactedScanReports(in, job)) {
				f.Job = name.Value
				findings = append(findings, f)
			}
		}
		// expire_in is checked on the jobs GitLab runs, with artifacts:
		// deep-merged along extends:, so it may come from a template.
		if !runsInheritedJob(in, name, job) {
			return
		}
		chain := in.Chain(job, "artifacts")
		if len(chain) == 0 {
			return
		}
		for _, a := range chain {
			if _, e := parser.FindKeyNode(a, "expire_in"); e != nil {
				return
			}
		}
		f := missingExpireIn(chain[0], file)
		f.Job = name.Value
		findings = append(findings, f)
	})

	return findings
}

// in is nil for the artifacts block under default:. reports are the files the
// job's script writes as unredacted secret scanner reports.
func checkArtifactPaths(doc *yaml.Node, in *Inheritance, node *yaml.Node, file string, reports []string) []finding.Finding {
	var findings []finding.Finding

	for _, section := range []string{"paths", "exclude"} {
		seqNode := parser.FindKey(node, section)
		if seqNode == nil || seqNode.Kind != yaml.SequenceNode {
			continue
		}
		for _, item := range seqNode.Content {
			if item.Kind != yaml.ScalarNode {
				continue
			}
			if section == "paths" && writesPlaceholderOnly(doc, in, node, item.Value) {
				continue
			}
			// Excluding a sensitive file is the fix, not the problem.
			found := checkArtifactPath(item, file, section == "paths")
			if section == "paths" && len(found) == 0 {
				if report := uploadedReport(item.Value, reports); report != "" {
					found = append(found, finding.Finding{
						RuleID:   "GL005",
						Severity: finding.Error,
						Message:  fmt.Sprintf("artifact path %q uploads the gitleaks report %q, which holds every secret the scan found in plain text — add --redact to the gitleaks command, or don't keep the report as an artifact", item.Value, report),
						File:     file,
						Line:     item.Line,
						Col:      item.Column,
					})
				}
			}
			findings = append(findings, found...)
		}
	}

	return findings
}

// unredactedScanReports returns the files the job's script writes as a
// gitleaks report without --redact: the report then holds each secret the
// scan found in plain text (#1296). --redact=0 redacts nothing.
func unredactedScanReports(in *Inheritance, job *yaml.Node) []string {
	var reports []string
	for _, line := range CollectJobScriptLines(in.Effective(job)) {
		if !strings.Contains(line.Value, "gitleaks") {
			continue
		}
		for _, cmd := range shellCommands(line.Value) {
			words := commandWords(cmd.text)
			if commandName(words) != "gitleaks" {
				continue
			}
			report, redacted := "", false
			for i := 1; i < len(words); i++ {
				w := words[i]
				switch {
				case w == "--redact":
					redacted = true
				case strings.HasPrefix(w, "--redact="):
					redacted = strings.TrimPrefix(w, "--redact=") != "0"
				case (w == "--report-path" || w == "-r") && i+1 < len(words):
					i++
					report = words[i]
				case strings.HasPrefix(w, "--report-path="):
					report = strings.TrimPrefix(w, "--report-path=")
				}
			}
			if report != "" && report != "-" && !strings.HasPrefix(report, "/dev/") && !redacted {
				reports = append(reports, artifactPath(report))
			}
		}
	}
	return reports
}

// uploadedReport returns the report an artifacts:paths entry uploads: the
// file itself, a directory that holds it, or a glob that matches it.
func uploadedReport(entry string, reports []string) string {
	entry = artifactPath(entry)
	for _, report := range reports {
		dir := strings.TrimSuffix(entry, "/")
		if entry == report || strings.HasPrefix(report, dir+"/") {
			return report
		}
		if ok, _ := path.Match(entry, report); ok {
			return report
		}
	}
	return ""
}

func missingExpireIn(node *yaml.Node, file string) finding.Finding {
	return finding.Finding{
		RuleID:   "GL005",
		Severity: finding.Warn,
		Message:  "artifacts block has no \"expire_in\" — artifacts are kept as long as the instance default allows (30 days on GitLab.com, possibly forever on a self-managed instance), increasing the exposure window for any sensitive content",
		File:     file,
		Line:     node.Line,
		Col:      node.Column,
	}
}

func checkArtifactPath(item *yaml.Node, file string, sensitive bool) []finding.Finding {
	var findings []finding.Finding
	path := item.Value

	switch {
	case strings.HasPrefix(path, "/"):
		findings = append(findings, finding.Finding{
			RuleID:   "GL005",
			Severity: finding.Error,
			Message:  fmt.Sprintf("artifact path %q is an absolute path — references the host filesystem directly and can exfiltrate arbitrary files on shell executors", path),
			File:     file,
			Line:     item.Line,
			Col:      item.Column,
		})
	case strings.Contains(path, "../"):
		findings = append(findings, finding.Finding{
			RuleID:   "GL005",
			Severity: finding.Error,
			Message:  fmt.Sprintf("artifact path %q contains path traversal — can escape the project directory on shell executors", path),
			File:     file,
			Line:     item.Line,
			Col:      item.Column,
		})
	case sensitive:
		var message string
		if pat := matchesSensitivePattern(path); pat != "" {
			message = fmt.Sprintf("artifact path %q matches sensitive file pattern %q — exclude secrets from artifacts", path, pat)
		} else if isWholeProjectArtifactPath(path) {
			message = fmt.Sprintf("artifact path %q uploads the whole working directory, potentially including generated secrets — list only required artifact paths", path)
		} else if strings.Contains("/"+path+"/", "/.git/") && !gitLogOnlyPath(path) {
			message = fmt.Sprintf("artifact path %q includes a .git directory — artifacts can expose repository history and Git configuration; exclude .git from artifact paths", path)
		}
		if message != "" {
			findings = append(findings, finding.Finding{
				RuleID:   "GL005",
				Severity: finding.Error,
				Message:  message,
				File:     file,
				Line:     item.Line,
				Col:      item.Column,
			})
		}
	}

	return findings
}

func isWholeProjectArtifactPath(path string) bool {
	switch strings.TrimSuffix(path, "/") {
	case ".", "*", "**", "$CI_PROJECT_DIR", "${CI_PROJECT_DIR}":
		return true
	}
	return false
}

// isGitlabReportArtifact reports whether path names one of GitLab's standard
// security-report artifacts, matched on the base name so directory prefixes
// such as tmp/ are covered too.
func isGitlabReportArtifact(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	for _, name := range gitlabReportArtifacts {
		if base == name {
			return true
		}
	}
	return false
}

func matchesSensitivePattern(path string) string {
	if isGitlabReportArtifact(path) {
		return ""
	}
	base := filepath.Base(path)
	// also check the full path for patterns like "*secret*"
	targets := []string{base, strings.ToLower(base), strings.ToLower(path)}

	for _, pat := range sensitivePatterns {
		for _, target := range targets {
			if ok, _ := filepath.Match(pat, target); ok {
				return pat
			}
		}
	}
	lower := "/" + strings.TrimPrefix(strings.ToLower(filepath.ToSlash(path)), "./")
	for _, pat := range sensitivePathPatterns {
		if strings.HasSuffix(lower, "/"+pat) {
			return pat
		}
	}
	return ""
}

// gitLogOnlyPath reports a path inside .git that holds only logs, such as
// Git LFS's error logs (.git/lfs/logs): no history and no configuration
// (#999).
func gitLogOnlyPath(path string) bool {
	p := "/" + strings.Trim(path, "/") + "/"
	i := strings.Index(p, "/.git/")
	if i < 0 {
		return false
	}
	rest := p[i+len("/.git/"):]
	return strings.HasPrefix(rest, "lfs/logs/")
}
