// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl095 struct{}

// GL095 flags a script that reaches for the runner's own identity: the cloud
// instance metadata service (IMDS) or the Kubernetes service-account token. On a
// cloud VM or in a cluster the runner holds credentials of its own — the instance
// role, the pod's service account — that belong to the infrastructure, not to the
// project. A pipeline that reads them takes an identity it was never granted and
// can move from the build into the surrounding account or cluster. The fix is a
// scoped, keyless credential minted through `id_tokens:`, not the runner's ambient
// identity (#1426). Retrieving a credential is an error; merely querying the
// metadata host for facts (region, project id) is a warn with the same advice.
var GL095 = &gl095{}

func (r *gl095) ID() string { return "GL095" }

// gl095CloudCredRe matches the credential path of a metadata request: the AWS
// role-credential and IMDSv2-token paths, the GCP service-account token, and the
// Azure OAuth2 token. Reaching one of these retrieves the runner's cloud
// identity, not just host facts. The pattern holds only URL paths and no host
// literal, so it is not an unanchored host regexp.
var gl095CloudCredRe = mustCompilePrefiltered(
	`iam/security-credentials|latest/api/token|service-accounts/[^"'\s]*token|identity/oauth2/token`)

// gl095K8sTokenPath is the runner pod's Kubernetes service-account token, i.e.
// its cluster identity. Matched as a literal string, so the `kubernetes.io`
// authority is not an unanchored host regexp.
const gl095K8sTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// gl095MetaHosts are the cloud instance metadata endpoints: the AWS/Azure
// link-local address and the GCP metadata hostname. Matched by a plain string
// scan rather than a regexp, so a lookalike domain cannot slip in and so the
// pattern is not an unanchored host regexp.
var gl095MetaHosts = []string{"169.254.169.254", "metadata.google.internal"}

func gl095IsHostByte(b byte) bool {
	return b >= '0' && b <= '9' ||
		b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' ||
		b == '.' || b == '-' || b == '_'
}

// gl095ReachesMetaHost returns the metadata host referenced in text as its own
// token (bounded by non-host bytes), or "". A longer address (169.254.169.2544)
// or a lookalike domain (metadata.google.internal.evil.com) is not a match, and
// only the exact metadata IP matches, so an unrelated 169.254.x.x service does not.
func gl095ReachesMetaHost(text string) string {
	for _, h := range gl095MetaHosts {
		for i := 0; ; {
			j := strings.Index(text[i:], h)
			if j < 0 {
				break
			}
			j += i
			var before, after byte
			if j > 0 {
				before = text[j-1]
			}
			if end := j + len(h); end < len(text) {
				after = text[end]
			}
			if !gl095IsHostByte(before) && !gl095IsHostByte(after) {
				return h
			}
			i = j + len(h)
		}
	}
	return ""
}

// gl095Mentions is a cheap substring prefilter: a line with none of these anchors
// cannot match, so the shell parse is skipped. The cloud credential paths always
// sit on the same line as a metadata host, so only the host anchors and the
// Kubernetes token path need to be checked here.
func gl095Mentions(v string) bool {
	return strings.Contains(v, "169.254.169.254") ||
		strings.Contains(v, "metadata.google.internal") ||
		strings.Contains(v, "serviceaccount/token")
}

func (r *gl095) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		v := line.Value
		if !gl095Mentions(v) {
			return
		}
		sev, msg, trigger := gl095Assess(v)
		if msg == "" {
			return
		}
		off := 0
		if i := strings.Index(v, trigger); i >= 0 {
			off = i
		}
		ln, col := scriptMatchPos(line, off)
		findings = append(findings, finding.Finding{
			RuleID:   "GL095",
			Severity: sev,
			Job:      job,
			Message:  msg,
			File:     file,
			Line:     ln,
			Col:      col,
		})
	})
	return findings
}

const (
	gl095MsgK8s = "script reads the runner's Kubernetes service-account token " +
		"(/var/run/secrets/kubernetes.io/serviceaccount/token) — this takes the runner pod's " +
		"cluster identity; use a scoped credential of the job's own, not the pod's token, and remove this"
	gl095MsgCred = "script retrieves the runner's cloud credentials from the instance metadata service " +
		"— this takes the runner's own cloud identity to reach the account it runs in; mint a scoped OIDC " +
		"token with id_tokens: instead, and remove this"
	gl095MsgHost = "script queries the cloud instance metadata service — the metadata endpoint exposes the " +
		"runner's ambient cloud identity; prefer a scoped OIDC token (id_tokens:) over the runner's instance role"
)

// gl095Assess reports the most serious runner-identity access on a script line.
// It walks the simple commands so that a metadata address quoted in an echo (or
// sitting in a comment) is not read as an access. Retrieving a credential (the
// IMDS credential path, or the Kubernetes token file) is an error; reaching the
// metadata host without a credential path is a warn. The returned trigger is the
// matched text, used to point the finding at the right column.
func gl095Assess(v string) (finding.Severity, string, string) {
	warnTrigger := ""
	for _, cmd := range shellCommands(v) {
		words := commandWords(cmd.text)
		// echo/printf of a metadata address is prose, not an access.
		if printsOnly(cmd, words) {
			continue
		}
		t := cmd.text
		if strings.Contains(t, gl095K8sTokenPath) {
			return finding.Error, gl095MsgK8s, gl095K8sTokenPath
		}
		if m := gl095CloudCredRe.FindString(t); m != "" {
			return finding.Error, gl095MsgCred, m
		}
		if warnTrigger == "" {
			if m := gl095ReachesMetaHost(t); m != "" {
				warnTrigger = m
			}
		}
	}
	if warnTrigger != "" {
		return finding.Warn, gl095MsgHost, warnTrigger
	}
	return finding.Info, "", ""
}
