package rules

import (
	"fmt"
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl083 struct{}

var GL083 = &gl083{}

func (r *gl083) ID() string { return "GL083" }

var (
	// socketRedirRe matches a redirect to a raw TCP/UDP socket, the bash-only
	// /dev/tcp/host/port device.
	socketRedirRe = regexp.MustCompile(`/dev/(?:tcp|udp)/`)
	// interactiveShellRe matches a shell invoked with the interactive flag, in
	// any of the -i, -it, -si spellings.
	interactiveShellRe = regexp.MustCompile(`\b(?:ba|z|k|da)?sh\b[^|;&]*\s-[a-zA-Z]*i\b`)
	// socketExecRe matches a socket opened read-write on a file descriptor:
	// exec 5<>/dev/tcp/host/port. The read-write form is what distinguishes it
	// from a one-way connectivity probe.
	socketExecRe = regexp.MustCompile(`\bexec\s+\d+<>\s*/dev/(?:tcp|udp)/`)

	// netcatExecRe matches netcat asked to run a program on connect. -e and -c
	// are the traditional and ncat spellings; both hand a shell to the peer.
	netcatExecRe = regexp.MustCompile(`\b(?:nc|ncat|netcat)(?:\.traditional|\.openbsd)?\b[^|;&]*(?:\s-[a-zA-Z]*[ec]\b|\s--(?:exec|sh-exec|lua-exec)\b)`)
	// netcatRe matches any netcat invocation, used only in combination with mkfifo.
	netcatRe = regexp.MustCompile(`\b(?:nc|ncat|netcat)(?:\.traditional|\.openbsd)?\b`)
	mkfifoRe = regexp.MustCompile(`\bmkfifo\b`)

	// socatExecRe matches socat wired to a program endpoint. socat address
	// keywords are case-insensitive.
	socatRe     = regexp.MustCompile(`\bsocat\b`)
	socatExecRe = regexp.MustCompile(`(?i)\b(?:exec|system):`)

	// interpreterRe, socketAPIRe and interpreterExecRe together match the
	// scripting-language one-liners: an interpreter that opens a socket and
	// hands it to a shell.
	interpreterRe     = regexp.MustCompile(`\b(?:python[23]?(?:\.\d+)?|perl|ruby)\b`)
	socketAPIRe       = regexp.MustCompile(`\bsocket\.socket\b|\bTCPSocket\b|\bIO::Socket::INET\b|\bSocket::inet_aton\b|\bsocket\.AF_INET\b`)
	interpreterExecRe = regexp.MustCompile(`\bos\.dup2\b|\bsubprocess\.(?:call|Popen|run|check_call)\b|\bpty\.spawn\b|\bexecl?\b|>&\s*S\b`)
)

// reverseShellKind returns a short description of the reverse-shell pattern in
// line, or the empty string when the line carries none.
//
// Every check requires a combination. Each individual token here has ordinary
// uses in CI: /dev/tcp is the standard wait-for-service probe, socat forwards
// ports, nc -l is a throwaway test listener and mkfifo tees logs. It is the
// pairing that has no innocent reading.
//
// Quoted substrings are deliberately not stripped the way GL011 strips them:
// a reverse shell is routinely wrapped as bash -c "bash -i >& /dev/tcp/...",
// and removing quotes first would remove the payload.
func reverseShellKind(line string) string {
	switch {
	case socketRedirRe.MatchString(line) && (interactiveShellRe.MatchString(line) || socketExecRe.MatchString(line)):
		return "shell redirected to a socket"
	case netcatExecRe.MatchString(line):
		return "netcat with command execution"
	case mkfifoRe.MatchString(line) && netcatRe.MatchString(line):
		return "named-pipe backdoor"
	case socatRe.MatchString(line) && socatExecRe.MatchString(line):
		return "socat with a program endpoint"
	case interpreterRe.MatchString(line) && socketAPIRe.MatchString(line) && interpreterExecRe.MatchString(line):
		return "interpreter socket one-liner"
	}
	return ""
}

func (r *gl083) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(item *yaml.Node, file, job string) {
		kind := reverseShellKind(item.Value)
		if kind == "" {
			return
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL083",
			Severity: finding.Error,
			Message: fmt.Sprintf(
				"script line opens a shell to a remote host (%s): %q — this is a reverse shell; remove it",
				kind, truncate(item.Value, 80),
			),
			File: file,
			Line: item.Line,
			Col:  item.Column,
			Job:  job,
		})
	})
	return findings
}
