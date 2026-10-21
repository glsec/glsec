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

type gl083 struct{}

var GL083 = &gl083{}

func (r *gl083) ID() string { return "GL083" }

var (
	// socketRedirRe matches a redirect to a raw TCP/UDP socket, the bash-only
	// /dev/tcp/host/port device.
	socketRedirRe = regexp.MustCompile(`/dev/(?:tcp|udp)/`)
	// interactiveShellRe matches a shell invoked with the interactive flag, in
	// any of the -i, -it, -si spellings. The interactive flag is what separates
	// a reverse shell from the wait-for-service probe, which opens the socket
	// and closes it again without ever attaching a shell to it.
	interactiveShellRe = regexp.MustCompile(`\b(?:ba|z|k|da)?sh\b[^|;&\n]*\s-[a-zA-Z]*i\b`)

	// netcatExecRe matches netcat asked to run a *shell* on connect. The flag
	// alone is not enough: nc -lc "printf ..." is a one-shot HTTP responder, so
	// the argument has to name a shell.
	netcatExecRe = regexp.MustCompile(`\b(?:nc|ncat|netcat)(?:\.traditional|\.openbsd)?\b[^|;&\n]*(?:\s-[a-zA-Z]*[ec]\b|\s--(?:exec|sh-exec|lua-exec)\b)\s*['"]?\S*(?:\bsh\b|\bbash\b|\bzsh\b|\bash\b|\bdash\b|\bcmd(?:\.exe)?\b|\bpowershell\b)`)
	// netcatRe matches any netcat invocation, used only in combination with mkfifo.
	netcatRe = regexp.MustCompile(`\b(?:nc|ncat|netcat)(?:\.traditional|\.openbsd)?\b`)
	mkfifoRe = regexp.MustCompile(`\bmkfifo\b`)

	// socatRe, socatExecRe and socatNetRe together match socat wiring a program
	// to a network peer. A program endpoint on its own is ordinary usage:
	// socat EXEC:'...' STDIO drives a local command and never opens a socket.
	// socat address keywords are case-insensitive.
	socatRe     = regexp.MustCompile(`\bsocat\b`)
	socatExecRe = regexp.MustCompile(`(?i)\b(?:exec|system):`)
	socatNetRe  = regexp.MustCompile(`(?i)\b(?:tcp|udp|openssl|ssl|socks[45]a?)[46]?(?:-[a-z]+)?:`)

	// interpreterRe, socketAPIRe and interpreterExecRe together match the
	// scripting-language one-liners: an interpreter that opens a socket and
	// hands it to a shell.
	interpreterRe     = regexp.MustCompile(`\b(?:python[23]?(?:\.\d+)?|perl|ruby)\b`)
	socketAPIRe       = regexp.MustCompile(`\bsocket\.socket\b|\bTCPSocket\b|\bIO::Socket::INET\b|\bSocket::inet_aton\b|\bsocket\.AF_INET\b`)
	interpreterExecRe = regexp.MustCompile(`\bos\.dup2\b|\bsubprocess\.(?:call|Popen|run|check_call)\b|\bpty\.spawn\b|\bexecl?\b|>&\s*S\b`)
)

// reverseShellKind returns a short description of the reverse-shell pattern in
// line, or the empty string when the line carries none. line is a single
// physical line, never a whole block scalar: the character classes below skip
// over shell separators, and letting them run past a newline would pair a
// netcat on one line of a `|` block with a shell flag several lines down.
//
// Every check requires a combination. Each individual token here has ordinary
// uses in CI: /dev/tcp is the standard wait-for-service probe, socat drives
// local commands and forwards ports, nc -l is a throwaway test listener and
// mkfifo tees logs. It is the pairing that has no innocent reading.
//
// Quoted substrings are deliberately not stripped the way GL011 strips them:
// a reverse shell is routinely wrapped as bash -c "bash -i >& /dev/tcp/...",
// and removing quotes first would remove the payload.
func reverseShellKind(line string) string {
	switch {
	case socketRedirRe.MatchString(line) && interactiveShellRe.MatchString(line):
		return "shell redirected to a socket"
	case netcatExecRe.MatchString(line):
		return "netcat with command execution"
	case mkfifoRe.MatchString(line) && netcatRe.MatchString(line):
		return "named-pipe backdoor"
	case socatRe.MatchString(line) && socatExecRe.MatchString(line) && socatNetRe.MatchString(line):
		return "socat with a program endpoint"
	case interpreterRe.MatchString(line) && socketAPIRe.MatchString(line) && interpreterExecRe.MatchString(line):
		return "interpreter socket one-liner"
	}
	return ""
}

func (r *gl083) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(item *yaml.Node, file, job string) {
		kind, payload, exfil := scanReverseShell(item.Value)
		severity := finding.Error
		msg := "script line opens a shell to a remote host (%s): %q — this is a reverse shell; remove it"
		switch {
		case exfil && strings.HasPrefix(kind, "environment"):
			msg = "script line sends the job environment to a network host (%s): %q — that includes CI_JOB_TOKEN and every masked variable; send only the variables the receiver needs"
		case exfil:
			msg = "script line sends a credential to a network host (%s): %q — this exfiltrates secrets from the runner; remove it"
		case kind == "":
			kind, payload = scanProcessMemory(item.Value)
			if kind == "" {
				return
			}
			severity = finding.Warn
			msg = "script line reads another process's memory (%s): %q — CI jobs have no reason to; this is how injected code scrapes masked secrets from the runner"
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL083",
			Severity: severity,
			Message:  fmt.Sprintf(msg, kind, truncate(payload, 80)),
			File:     file,
			Line:     item.Line,
			Col:      item.Column,
			Job:      job,
		})
	})
	return findings
}

// scanReverseShell evaluates each physical line of a script item separately and
// returns the first pattern found along with the line carrying it. A block
// scalar arrives here as one item, so splitting is what keeps a match anchored
// to a single command.
func scanReverseShell(value string) (kind, payload string, exfil bool) {
	for _, line := range strings.Split(value, "\n") {
		if k := reverseShellKind(line); k != "" {
			return k, strings.TrimSpace(line), false
		}
		if k := credentialExfilKind(line); k != "" {
			return k, strings.TrimSpace(line), true
		}
	}
	return "", "", false
}

var (
	// credFileRe matches a well-known credential file in a home directory.
	// Group 1 is the ".pub" suffix of an SSH key, which marks a public key.
	credFileRe = regexp.MustCompile(`(?:~|\$HOME|\$\{HOME\}|/root|/home/[\w.-]+)/(?:\.ssh/id_[\w-]+(\.pub)?|\.aws/credentials|\.docker/config\.json|\.kube/config|\.netrc|\.git-credentials|\.config/gcloud/[\w.-]+)`)
	// tokenMintRe matches a command that prints a live cloud access token.
	tokenMintRe = regexp.MustCompile(`\bgcloud\s+auth\s+print-(?:access|identity)-token\b|\baws\s+ecr\s+get-login-password\b|\baz\s+account\s+get-access-token\b`)

	// uploadFlagRe matches an upload option whose value is a local file that
	// the tool sends: curl -F name=@file, -d @file, --data-binary @file,
	// -T file, --upload-file file, and wget --post-file=file. Only the
	// credential right after the option counts, so `curl --netrc-file
	// ~/.netrc` (authenticating with the file, not sending it) stays quiet.
	uploadFlagRe = regexp.MustCompile(`(?:-F[ \t]*["']?[\w.-]*=@|-d[ \t]*["']?@|--data(?:-binary|-raw|-urlencode)?(?:=|[ \t]+)["']?@|-T[ \t]*["']?|--upload-file(?:=|[ \t]+)["']?|--post-file(?:=|[ \t]*)["']?)$`)
	// stdinSinkRe matches a network tool that sends what it reads on stdin.
	stdinSinkRe   = regexp.MustCompile(`\b(?:nc|ncat|netcat)(?:\.traditional|\.openbsd)?\b|\bcurl\b.*(?:@-|-T[ \t]*-(?:\s|$)|--upload-file[ \t]+-(?:\s|$))|\bwget\b.*--post-file[= \t]*/dev/stdin`)
	socketWriteRe = regexp.MustCompile(`>[ \t]*/dev/(?:tcp|udp)/`)
	scpRe         = regexp.MustCompile(`\bscp\b`)
	scpIdentityRe = regexp.MustCompile(`-i[ \t]*$`)
	scpRemoteRe   = regexp.MustCompile(`\s[\w.@-]+:\S*`)
	writeTargetRe = regexp.MustCompile(`>>?[ \t]*["']?$`)
)

// credentialExfilKind returns a short description of how line sends a
// credential off the runner, or the empty string. Like reverseShellKind it
// needs a combination: reading these files is routine (a job builds its
// kubeconfig, logs in to a registry), and so is talking to the network. It is
// the credential reaching a raw network send that has no innocent reading.
func credentialExfilKind(line string) string {
	var creds [][]int
	for _, m := range credFileRe.FindAllStringSubmatchIndex(line, -1) {
		if m[2] >= 0 {
			continue // public key
		}
		if writeTargetRe.MatchString(line[:m[0]]) {
			continue // the job writes this file
		}
		creds = append(creds, m)
	}
	for _, m := range creds {
		if uploadFlagRe.MatchString(line[:m[0]]) {
			return "credential file uploaded"
		}
	}
	if (len(creds) > 0 || tokenMintRe.MatchString(line)) && socketWriteRe.MatchString(line) {
		return "credential written to a socket"
	}
	if k := environmentExfilKind(line); k != "" {
		return k
	}
	if k := pipedCredential(line); k != "" {
		return k
	}
	if scpRe.MatchString(line) {
		for _, m := range creds {
			before := line[:m[0]]
			if strings.HasSuffix(before, ":") || scpIdentityRe.MatchString(before) {
				continue // remote source path, or the identity scp logs in with
			}
			if scpRemoteRe.MatchString(line[m[1]:]) {
				return "credential copied to a remote host"
			}
		}
	}
	return ""
}

// pipedCredential reports a credential produced in one pipeline stage and
// consumed by a network send in a later one. `||` is not a pipe.
func pipedCredential(line string) string {
	stages := strings.Split(strings.ReplaceAll(line, "||", "\x00\x00"), "|")
	for i, st := range stages[:len(stages)-1] {
		src := false
		if tokenMintRe.MatchString(st) {
			src = true
		}
		for _, m := range credFileRe.FindAllStringSubmatchIndex(st, -1) {
			if m[2] < 0 && !writeTargetRe.MatchString(st[:m[0]]) {
				src = true
			}
		}
		if !src {
			continue
		}
		for _, sink := range stages[i+1:] {
			if stdinSinkRe.MatchString(sink) {
				return "credential piped to a network tool"
			}
		}
	}
	return ""
}

var (
	// procSecretRe matches another process's environment or memory under
	// /proc, by PID, glob, self, or a variable or command substitution.
	procSecretRe = regexp.MustCompile(`/proc/(?:\d+|self|\*|\$\{?\w+\}?|\$\([^)]*\))/(?:environ|mem)\b`)
	// procMemRe matches process memory specifically; reading it is suspect
	// even without a network send.
	procMemRe = regexp.MustCompile(`/proc/(?:\d+|self|\*|\$\{?\w+\}?|\$\([^)]*\))/mem\b`)
	// psEnvRe matches BSD-style ps with the e modifier, which prints every
	// process's environment (ps auxe, ps eww). ps -e only selects processes, and
	// ps must be the command, not a subcommand such as docker compose ps.
	psEnvRe = regexp.MustCompile(`(?:^|[;&|(]|\$\()\s*(?:sudo\s+)?ps\s+[a-zA-Z]*e[a-zA-Z]*(?:\s|$)`)
	// envSubstRe matches $(...) (one level of nested parentheses) and `...`.
	envSubstRe = regexp.MustCompile("\\$\\(((?:[^()]|\\([^()]*\\))*)\\)|`([^`]*)`")
	netToolRe  = regexp.MustCompile(`\b(?:curl|wget|nc|ncat|netcat)\b`)
)

// environmentSource reports whether a command fragment produces the job's
// environment or another process's: a bare env/printenv, /proc/<pid>/environ
// or /mem, or ps with the e modifier.
func environmentSource(s string) bool {
	return envFullDumpRe.MatchString(s) || procSecretRe.MatchString(s) || psEnvRe.MatchString(s)
}

// environmentExfilKind reports the job's environment, which holds every CI/CD
// variable including masked ones, reaching a network send on the same line.
func environmentExfilKind(line string) string {
	stages := strings.Split(strings.ReplaceAll(line, "||", "\x00\x00"), "|")
	for i, st := range stages[:len(stages)-1] {
		if !environmentSource(st) {
			continue
		}
		for _, sink := range stages[i+1:] {
			if stdinSinkRe.MatchString(sink) {
				return "environment piped to a network tool"
			}
		}
	}
	for _, m := range envSubstRe.FindAllStringSubmatchIndex(line, -1) {
		inner := ""
		switch {
		case m[2] >= 0:
			inner = line[m[2]:m[3]]
		case m[4] >= 0:
			inner = line[m[4]:m[5]]
		}
		outside := line[:m[0]] + " " + line[m[1]:]
		if environmentSource(strings.TrimSpace(inner)) && netToolRe.MatchString(outside) {
			return "environment sent in a request"
		}
	}
	if socketWriteRe.MatchString(line) {
		before := line[:socketWriteRe.FindStringIndex(line)[0]]
		if environmentSource(before) {
			return "environment written to a socket"
		}
	}
	return ""
}

// scanProcessMemory returns the first line of value that reads another
// process's memory through /proc.
func scanProcessMemory(value string) (kind, payload string) {
	for _, line := range strings.Split(value, "\n") {
		if procMemRe.MatchString(line) {
			return "process memory read", strings.TrimSpace(line)
		}
	}
	return "", ""
}
