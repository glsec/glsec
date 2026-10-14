// Command glsec is a security linter for GitLab CI/CD configuration files
// (.gitlab-ci.yml). It reports misconfigurations that can lead to supply-chain
// attacks, secret leakage and token exfiltration.
//
// Usage:
//
//	glsec [flags] [file ...]
//	glsec explain <RULE-ID>
//	glsec list [--format text|json] [--owasp CICD-SEC-N]
//
// Run glsec -h for the flags and see https://github.com/glsec/glsec for the
// full documentation.
package main
