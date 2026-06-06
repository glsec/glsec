package rules

import (
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl069 struct{}

var GL069 = &gl069{}

func (r *gl069) ID() string { return "GL069" }

type pkgAuthCheck struct {
	re  *regexp.Regexp
	msg string
}

// pkgAuthChecks match package-manager invocations that turn off signature /
// authentication verification (a different control from TLS verification, which
// GL042 covers). Each is a high-signal, explicit bypass flag.
var pkgAuthChecks = []pkgAuthCheck{
	{
		re:  regexp.MustCompile(`--allow-unauthenticated\b`),
		msg: `apt "--allow-unauthenticated" disables package signature verification — an unsigned or tampered package from a compromised or MITM'd mirror would install without error; import the repository signing key and reference it with signed-by= instead`,
	},
	{
		re:  regexp.MustCompile(`(?i)allowunauthenticated"?\s*=\s*"?(?:true|1|yes)\b`),
		msg: `apt option "APT::Get::AllowUnauthenticated=true" disables package signature verification — unsigned packages install without error; keep verification on and trust the repository via its signing key (signed-by=) instead`,
	},
	{
		re:  regexp.MustCompile(`(?i)\[[^][]*\btrusted\s*=\s*(?:yes|true|1)\b[^][]*\]`),
		msg: `apt source marked "[trusted=yes]" disables package signature verification for that repository — use "signed-by=<keyring>" to verify packages against the repository's GPG key instead`,
	},
	{
		re:  regexp.MustCompile(`--allow-untrusted\b`),
		msg: `apk "--allow-untrusted" disables package signature verification — an unsigned or tampered package would install without error; add the repository's signing key to /etc/apk/keys instead`,
	},
}

func (r *gl069) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		if strings.HasPrefix(strings.TrimSpace(line.Value), "#") {
			return
		}
		for _, c := range pkgAuthChecks {
			if !c.re.MatchString(line.Value) {
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   "GL069",
				Severity: finding.Warn,
				Job:      job,
				Message:  c.msg,
				File:     file,
				Line:     line.Line,
				Col:      line.Column,
			})
			break
		}
	})
	return findings
}
