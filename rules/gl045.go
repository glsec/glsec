// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl045 struct{}

var GL045 = &gl045{}

func (r *gl045) ID() string { return "GL045" }

// releasePushRe matches script lines that push artifacts to a registry or package index.
var releasePushRe = regexp.MustCompile(
	`\bdocker\s+push\b` +
		`|\bcrane\s+push\b` +
		`|\bhelm\s+push\b` +
		`|\btwine\s+upload\b` +
		`|\bcargo\s+publish\b` +
		`|\bnpm\s+publish\b` +
		`|\bgoreleaser\s+release\b`,
)

// ephemeralTagRe marks a push whose target is not a consumer release: a
// per-merge-request preview (an `mr-` tag or a merge-request variable) or a
// moving branch-slug tag. A consumer release is tied to a tag/version, so
// nobody downstream verifies a signature on these (#1100).
var ephemeralTagRe = regexp.MustCompile(
	`(?i)mr-\$?\{?CI_MERGE_REQUEST|[:=]\s*mr-|\bCI_MERGE_REQUEST_IID\b|\bCI_MERGE_REQUEST_REF_PATH\b` +
		`|:\$\{?CI_COMMIT_REF_SLUG\}?|:\$\{?CI_COMMIT_REF_NAME\}?` +
		`|--tag[= ]\$?\{?CI_COMMIT_REF_SLUG\}?`,
)

// mrScopedEnv reports an environment: scoped to a merge request, e.g.
// environment: { name: "mr/$CI_MERGE_REQUEST_IID" } — a per-MR preview, not a
// release target.
func mrScopedEnv(env *yaml.Node) bool {
	if env == nil {
		return false
	}
	name := ""
	switch env.Kind {
	case yaml.ScalarNode:
		name = env.Value
	case yaml.MappingNode:
		if n := parser.FindKey(env, "name"); n != nil && n.Kind == yaml.ScalarNode {
			name = n.Value
		}
	}
	lower := strings.ToLower(name)
	return strings.HasPrefix(lower, "mr/") || strings.Contains(lower, "merge_request") ||
		strings.Contains(lower, "merge-request") || strings.Contains(name, "CI_MERGE_REQUEST")
}

// releaseSigningRe matches script lines that cryptographically sign an artifact.
var releaseSigningRe = regexp.MustCompile(
	`\bcosign\s+sign\b` +
		`|\bgpg\b.*--detach-sign\b` +
		`|\bgpg\b.*\s-b\b` +
		`|\bnotation\s+sign\b` +
		`|\bslsa-verifier\b` +
		// Sigstore-backed provenance and attestations from the publish step:
		// npm publish --provenance, twine upload --attestations, uv publish
		// --trusted-publishing with attestations, and GitLab's attest step.
		`|\bnpm\b[^|;&]*\bpublish\b[^|;&]*--provenance\b` +
		`|\b(?:twine\s+upload|uv\s+publish)\b[^|;&]*--attestations\b` +
		`|\bgh\s+attestation\b|\bcosign\s+attest\b`,
)

func (r *gl045) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if !IsDeployLikeJob(name.Value, job) {
			return
		}
		// A per-MR preview deployment is ephemeral, not a consumer release.
		if mrScopedEnv(parser.FindKey(job, "environment")) {
			return
		}

		lines := CollectJobScriptLines(job)
		if len(lines) == 0 {
			return
		}

		var pushLine *yaml.Node
		hasSigning := false

		for _, line := range lines {
			if pushLine == nil && releasePushRe.MatchString(line.Value) && !ephemeralTagRe.MatchString(line.Value) {
				pushLine = line
			}
			if releaseSigningRe.MatchString(line.Value) {
				hasSigning = true
			}
		}

		if pushLine == nil || hasSigning {
			return
		}

		findings = append(findings, finding.Finding{
			RuleID:   "GL045",
			Severity: finding.Warn,
			Job:      name.Value,
			Message:  "release job pushes artifacts without a signing step — consumers cannot verify artifact integrity; add cosign, gpg --detach-sign, or notation sign",
			File:     file,
			Line:     pushLine.Line,
			Col:      pushLine.Column,
		})
	})

	return findings
}
