// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl070 struct{}

var GL070 = &gl070{}

func (r *gl070) ID() string { return "GL070" }

type staticCredCheck struct {
	match func(string) bool
	msg   string
}

var (
	// gcloud activate-service-account, or any gcloud --key-file. The keyless
	// WIF form uses --cred-file (not --key-file), so it is not matched.
	gcpKeyRe = regexp.MustCompile(`\bgcloud\b.*(?:\bactivate-service-account\b|--key-file\b)`)
	// aws configure set aws_secret_access_key …
	awsConfigRe = regexp.MustCompile(`\baws\s+configure\s+set\s+aws_secret_access_key\b`)
	// AWS_SECRET_ACCESS_KEY=… assigned/exported in a script line.
	awsEnvRe = regexp.MustCompile(`\bAWS_SECRET_ACCESS_KEY\s*=`)
)

// Indexes of the AWS checks in staticCredChecks.
const (
	awsConfigCheck = 1
	awsEnvCheck    = 2
)

var staticCredChecks = []staticCredCheck{
	{
		match: gcpKeyRe.MatchString,
		msg:   `gcloud authenticates with a static service-account key — a long-lived, broad, exfiltratable credential; use keyless Workload Identity Federation with an id_tokens: audience and gcloud auth login --cred-file instead`,
	},
	{
		match: awsConfigRe.MatchString,
		msg:   `aws configure set aws_secret_access_key uses a long-lived static access key — prefer keyless OIDC: an id_tokens: token with sts:AssumeRoleWithWebIdentity instead`,
	},
	{
		match: awsEnvRe.MatchString,
		msg:   `AWS_SECRET_ACCESS_KEY set in script uses a long-lived static access key — prefer keyless OIDC: an id_tokens: token with sts:AssumeRoleWithWebIdentity instead`,
	},
	{
		match: isAzureStaticLogin,
		msg:   `az login --service-principal with a static --password is a long-lived credential — use keyless OIDC: az login --service-principal --federated-token "$ID_TOKEN" with an id_tokens: audience instead`,
	},
}

// isAzureStaticLogin reports an az service-principal login that authenticates
// with a static password rather than a (keyless) federated OIDC token.
func isAzureStaticLogin(line string) bool {
	return strings.Contains(line, "az login") &&
		strings.Contains(line, "--service-principal") &&
		strings.Contains(line, "--password") &&
		!strings.Contains(line, "--federated-token")
}

// awsSTSRe matches the keyless AWS flow: credentials from sts assume-role,
// usually with the job's OIDC token (--web-identity-token).
var awsSTSRe = regexp.MustCompile(`\bsts\s+assume-role|--web-identity-token\b`)

func (r *gl070) Check(doc *yaml.Node, file string) []finding.Finding {
	// Jobs that get their AWS credentials from STS: the AWS_SECRET_ACCESS_KEY
	// they set is short-lived, the flow this rule recommends.
	sts := map[string]bool{}
	// Per-line results, cached for lines shared through an anchor (#766).
	usesSTS := nodeMemo[bool]{}
	matches := nodeMemo[[]int]{}
	EachScriptLinePerJob(doc, file, func(line *yaml.Node, file, job string) {
		if usesSTS.get(line, func() bool { return awsSTSRe.MatchString(line.Value) }) {
			sts[job] = true
		}
	})

	var findings []finding.Finding
	EachScriptLinePerJob(doc, file, func(line *yaml.Node, file, job string) {
		hits := matches.get(line, func() []int {
			if strings.HasPrefix(strings.TrimSpace(line.Value), "#") {
				return nil
			}
			var out []int
			for i, c := range staticCredChecks {
				if c.match(line.Value) {
					out = append(out, i)
				}
			}
			return out
		})
		for _, i := range hits {
			c := staticCredChecks[i]
			if sts[job] && (i == awsConfigCheck || i == awsEnvCheck) {
				continue
			}
			at := 0
			for _, l := range logicalLines(line.Value) {
				if c.match(l.text) {
					at = l.line
					break
				}
			}
			ln, col := scriptLinePos(line, at)
			findings = append(findings, finding.Finding{
				RuleID:   "GL070",
				Severity: finding.Warn,
				Job:      job,
				Message:  c.msg,
				File:     file,
				Line:     ln,
				Col:      col,
			})
			break
		}
	})
	return findings
}
