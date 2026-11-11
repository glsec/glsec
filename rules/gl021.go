// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl021 struct{}

var GL021 = &gl021{}

func (r *gl021) ID() string { return "GL021" }

var (
	// gl021VarRefRe also accepts PowerShell's $env:NAME and ${env:NAME}.
	// The env: drive is case insensitive; the capture is the variable name.
	gl021VarRefRe = mustCompilePrefiltered(`\$\{?(?i:env:)?([A-Za-z_][A-Za-z0-9_]*)\}?`)

	// secretNameRe matches names carrying a secret indicator after at least one
	// character, anywhere in the name: SECRET_KEY_BASE and DEPLOY_TOKEN alike.
	secretNameRe = mustCompilePrefiltered(`^[A-Za-z_][A-Za-z0-9_]*(?:_TOKEN|_SECRET|_PASSWORD|_PASSWD|_PASS|_PWD|_KEY|_CREDENTIAL|_CERT)`)

	// nonSecretSuffixRe matches a final name segment that names something
	// about the secret rather than the secret itself: GPG_KEY_ID,
	// DOCKER_PASSWORD_FILE, DEPLOY_TOKENIZER_URL (#579). DIR also counts
	// without an underscore, as in DOCKER_TLS_CERTDIR. GIT_TOKEN_CONFIGURED is
	// a flag that a token is set (#1370).
	nonSecretSuffixRe = mustCompilePrefiltered(`(?:_(?:ID|URL|URI|PATH|FILE|NAME|HOST|USER|USERNAME|TYPE|LENGTH|EXPIRES_AT|VERSION|PACKAGE|ENDPOINT|DOMAIN|PORT|REGION|ENABLED|CONFIGURED|MODE)|DIR)$`)

	// singleQuotedRe matches single-quoted spans, whose contents the shell does
	// not expand (so a secret reference inside them is literal text).
	singleQuotedRe = mustCompilePrefiltered(`'[^']*'`)

	// A direct file redirect of PowerShell's information stream (or all
	// streams) suppresses host output. A merge such as 6>&1 is not a file.
	gl021InfoFileRedirectRe = mustCompilePrefiltered(`^(?:6|\*)>>?\s*[^&\s]`)
)

func (r *gl021) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	// An item shared by several jobs through an anchor is checked once (#766).
	seen := map[*yaml.Node]bool{}
	in := NewInheritance(doc)

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		scriptNodes := []*yaml.Node{
			parser.FindKey(job, "before_script"),
			parser.FindKey(job, "script"),
			parser.FindKey(job, "after_script"),
			hookScriptNode(job),
		}
		scriptNodes = append(scriptNodes, parser.RunStepBlocks(job)...)
		for _, node := range scriptNodes {
			if !isScriptList(node) {
				continue
			}
			for _, item := range node.Content {
				if item.Kind != yaml.ScalarNode || seen[item] {
					continue
				}
				seen[item] = true
				// Match per line: a `|` block scalar is one item but many
				// commands. A backslash continuation belongs to its line, so a
				// redirect or pipe on the next physical line still counts.
				for _, l := range logicalLines(item.Value) {
					i, line := l.line, l.text
					match, ok, viaEncoder := printedSecret(line)
					message := ""
					if ok && viaEncoder {
						message = fmt.Sprintf("script pipes secret variable %s into an encoder (base64/base32/xxd/…) — the encoded value reaches the job log, past GitLab's value masking", match)
					} else if ok {
						message = fmt.Sprintf("script prints secret variable %s — value may appear in job logs", match)
					} else if credentialFile := printedCredentialFile(line); credentialFile != "" {
						// A file the job writes with a placeholder holds no
						// token (#1285).
						if placeholderRCFiles[strings.ToLower(path.Base(credentialFile))] &&
							jobWritesPlaceholderOnly(in, job, normalizeWritePath(credentialFile)) {
							continue
						}
						message = fmt.Sprintf("script prints credential file %s — its contents may appear in job logs", credentialFile)
					} else {
						continue
					}
					findings = append(findings, finding.Finding{
						RuleID:   "GL021",
						Severity: finding.Warn,
						Job:      name.Value,
						Message:  message,
						File:     file,
						Line:     parser.ScalarContentLine(item, i),
						Col:      item.Column,
					})
				}
			}
		}
	})

	return findings
}

// The .docker entry is a directory; only its config.json is a credential file.
var gl021CredentialNames = []string{".npmrc", ".yarnrc.yml", ".pypirc", ".netrc", "_netrc", ".dockercfg", ".docker"}

// printedCredentialFile detects common credential files printed to stdout.
// Piped output is not logged unless the next command is tee.
func printedCredentialFile(line string) string {
	// Most script lines do not mention a credential file. Avoid shell parsing
	// and its allocations unless one of the supported names may be present.
	foundName := false
	for _, name := range gl021CredentialNames {
		if strings.Contains(line, name) {
			foundName = true
			break
		}
	}
	if !foundName {
		return ""
	}
	cmds := shellCommands(line)
	scanAt := 0
	for i, cmd := range cmds {
		at := -1
		if offset := strings.Index(line[scanAt:], cmd.text); offset >= 0 {
			at = scanAt + offset
			scanAt = at + len(cmd.text)
		}
		words := commandWords(cmd.text)
		if len(words) < 2 {
			continue
		}
		switch commandName(words) {
		case "cat", "head", "tail", "less", "more":
		default:
			continue
		}
		masked := maskShellQuotes(cmd.text)
		if stdoutRedirectRe.MatchString(masked) || strings.Contains(masked, "&>") || fewBytes(words) {
			continue
		}
		if cmd.piped {
			if i+1 >= len(cmds) || commandName(commandWords(cmds[i+1].text)) != "tee" {
				continue
			}
			next := maskShellQuotes(cmds[i+1].text)
			if stdoutRedirectRe.MatchString(next) || strings.Contains(next, "&>") {
				continue
			}
		}
		if at >= 0 && groupOutputDiverted(line, at+len(cmd.text)-1) {
			continue
		}
		for _, arg := range words[1:] {
			if offset := strings.Index(cmd.text, arg); at >= 0 && offset >= 0 && gl021InSubstitution(line[:at+offset]) {
				continue
			}
			name := path.Clean(strings.ReplaceAll(arg, `\`, "/"))
			for _, credential := range gl021CredentialNames {
				if credential == ".docker" {
					if strings.HasSuffix("/"+strings.TrimPrefix(name, "/"), "/.docker/config.json") {
						return arg
					}
				} else if path.Base(name) == credential {
					return arg
				}
			}
		}
	}
	return ""
}

// fewBytes reports head or tail printing at most 16 bytes, which checks a
// file without showing a token: head -c 5, tail --bytes=5 (#1285). tail -c +N
// prints from byte N to the end and counts as a print.
func fewBytes(words []string) bool {
	switch commandName(words) {
	case "head", "tail":
	default:
		return false
	}
	for i, w := range words[1:] {
		n := ""
		switch {
		case (w == "-c" || w == "--bytes") && i+2 < len(words):
			n = words[i+2]
		case strings.HasPrefix(w, "--bytes="):
			n = strings.TrimPrefix(w, "--bytes=")
		case strings.HasPrefix(w, "-c") && len(w) > 2:
			n = w[2:]
		default:
			continue
		}
		v, err := strconv.Atoi(n)
		return err == nil && n[0] != '+' && n[0] != '-' && v <= 16
	}
	return false
}

// gl021InSubstitution reports whether a command begins inside $(...).
func gl021InSubstitution(prefix string) bool {
	var quote byte
	var stack []byte
	for i := 0; i < len(prefix); i++ {
		c := prefix[i]
		switch {
		case c == '\\' && quote != '\'':
			i++
		case c == '\'' && quote != '"':
			if quote == '\'' {
				quote = 0
			} else {
				quote = '\''
			}
		case c == '"' && quote != '\'':
			if quote == '"' {
				quote = 0
			} else {
				quote = '"'
			}
		case c == '$' && quote != '\'' && i+1 < len(prefix) && prefix[i+1] == '(':
			stack = append(stack, quote)
			quote = 0
			i++
		case c == '(' && quote == 0 && len(stack) > 0:
			stack = append(stack, 0)
		case c == ')' && quote == 0 && len(stack) > 0:
			quote = stack[len(stack)-1]
			stack = stack[:len(stack)-1]
		}
	}
	return len(stack) > 0
}

// printedSecret reports whether a script line actually prints a secret variable
// to stdout/stderr (i.e. the job log). It returns false when the printed value
// is instead redirected to a file, piped into another command, captured by a
// command/process substitution, or single-quoted (not expanded) — none of which
// reach the log absent debug tracing. PowerShell's information stream is
// separate from success output and needs its own redirection.
func printedSecret(line string) (name string, printed, viaEncoder bool) {
	// A child shell expands its script itself, so a single-command
	// `bash -c "echo $DEPLOY_TOKEN"` (or the same with single quotes / eval)
	// prints the secret even though the outer command is not echo. Recurse
	// into that script before stripping quotes, then honour outer redirects.
	if mayHandScriptToChild(line) {
		if name, printed, viaEncoder, decided := childScriptPrintsSecret(line); decided {
			return name, printed, viaEncoder
		}
	}

	return printedSecretDirect(line)
}

// childScriptPrintsSecret reports a secret printed by the script a
// single-command line hands to a child shell or eval, unless the child's
// output is redirected, piped, or captured. decided is false when the child
// script prints nothing, so the caller goes on to check the line itself.
func childScriptPrintsSecret(line string) (name string, printed, viaEncoder, decided bool) {
	if script, ok := childPrintScript(line); ok && script != line {
		if name, printed, viaEncoder := printedSecret(script); printed {
			if childShellOutputDiverted(line) {
				return "", false, false, true
			}
			return name, true, viaEncoder, true
		}
	}
	return "", false, false, false
}

// mayHandScriptToChild is a cheap, allocation-free check that line could
// start a child shell, su, ssh or eval and reference a variable, so
// printedSecret only splits the line into words when that is possible.
func mayHandScriptToChild(line string) bool {
	if strings.IndexByte(line, '$') < 0 {
		return false
	}
	return strings.Contains(line, "sh") || strings.Contains(line, "eval") || strings.Contains(line, "su")
}

// printedSecretDirect is printedSecret for the line itself, without looking
// into a child shell script.
func printedSecretDirect(line string) (name string, printed, viaEncoder bool) {
	// Single-quoted spans are literal. Keep an empty quoted placeholder so a
	// filename such as 6> 'private log.txt' still has a redirection target.
	s := singleQuotedRe.ReplaceAllString(line, "''")
	// Command separators inside quoted arguments (such as the parentheses in
	// "${TOKEN:+ (set)}") are literal characters, not segment boundaries.
	// maskShellQuotes preserves offsets while hiding those separators.
	separators := maskShellQuotes(s)

	for _, loc := range gl021VarRefRe.FindAllStringSubmatchIndex(s, -1) {
		name := s[loc[2]:loc[3]]
		powerShell := strings.Contains(s[loc[0]:loc[2]], ":")
		if powerShell {
			name = strings.ToUpper(name) // Windows environment names are case insensitive.
		}
		if !isSecretName(name) {
			continue
		}
		start, end := loc[0], loc[1]
		// \$NAME prints the text $NAME, not the value (#982).
		if start > 0 && s[start-1] == '\\' {
			continue
		}
		// ${NAME:+word} outputs word (or nothing), never NAME's value.
		// Only exempt this reference: word may expand another secret, or a
		// later command on the same line may print NAME itself (#1300).
		// In contrast, ${NAME:-default} outputs NAME when it is set.
		if strings.HasPrefix(s[end:], ":+") {
			continue
		}
		// ${NAME:offset:length} with a literal length of at most 16 prints a
		// short slice of the value, like head -c 16, not the secret (#1370).
		if strings.HasPrefix(s[start:], "${") && shortSubstring(s[end:]) {
			continue
		}

		// Find the command segment the secret belongs to (split on shell
		// command separators).
		left := start - 1
		for left >= 0 && !isShellSep(separators[left]) {
			left--
		}
		right := end
		for right < len(s) && !isShellSep(separators[right]) {
			right++
		}

		// The secret must be an argument of a print command that is the
		// segment's command — not an `echo` buried inside a quoted argument to
		// another command (e.g. git config credential.helper "!echo $TOKEN").
		command := segmentPrintCommand(s[left+1 : start])
		if command == "" {
			// A child-shell command may execute a quoted script containing
			// separators (bash -c, eval, ssh, su, etc.). If the masked
			// segment has no print command, retry the original separators
			// to preserve the detection these scripts had before #1300.
			left = start - 1
			for left >= 0 && !isShellSep(s[left]) {
				left--
			}
			right = end
			for right < len(s) && !isShellSep(s[right]) {
				right++
			}
			command = segmentPrintCommand(s[left+1 : start])
			if command == "" {
				continue
			}
		}
		if powerShell || strings.HasPrefix(command, "write") {
			escapeStart := start
			for escapeStart > 0 && s[escapeStart-1] == '`' {
				escapeStart--
			}
			if (start-escapeStart)%2 != 0 {
				continue // An unpaired backtick makes the variable reference literal.
			}
		}
		seg := s[left+1 : right]
		if command == "write-host" || command == "write-information" {
			if informationRedirected(seg) {
				continue
			}
			return varRefText(s[start:end]), true, false
		}
		// Output redirected to a file (`>` / `>>`): not logged.
		if strings.Contains(seg, ">") {
			continue
		}
		// Inside `$(…)` or `<(…)` command/process substitution: captured, not
		// logged. A bare `(` is a subshell, whose output does reach the log.
		if left > 0 && s[left] == '(' && (s[left-1] == '$' || s[left-1] == '<') {
			continue
		}
		// Inside a { …; } group or ( … ) subshell whose output is redirected
		// or piped after the closing bracket (#982).
		if groupOutputDiverted(s, start) {
			continue
		}
		// Output piped into another command is normally not logged — the
		// suppression that keeps `echo "$PASS" | docker login --password-stdin`
		// quiet (#301, #295, #982). But a secret piped into an encoder or
		// pass-through printer whose output still reaches the log is a masking
		// bypass: GitLab masks the literal value, not its base64/hex form
		// (#1361). Report only that, leaving credential consumers silent.
		if right < len(s) && s[right] == '|' {
			if pipedSecretReachesLog(s, separators, right) {
				return varRefText(s[start:end]), true, true
			}
			continue
		}
		return varRefText(s[start:end]), true, false
	}
	return "", false, false
}

// logEncoders are commands that return their stdin on stdout, re-encoded
// (base64, base32, base16, xxd, od, hexdump, uuencode) or verbatim (tee, cat,
// rev, tr). A secret piped into one as a pipeline's terminal stage reaches the
// job log, past GitLab's value-based masking (#1361). A credential consumer
// (docker login --password-stdin, ssh-add -, gpg --passphrase-fd, kubectl
// --token-stdin, …) is deliberately absent, so a secret handed to one stays
// unreported, preserving the #301/#295/#982 false-positive fixes. Extend as a
// table.
var logEncoders = map[string]bool{
	"base64": true, "base32": true, "base16": true, "basenc": true,
	"xxd": true, "od": true, "hexdump": true, "uuencode": true,
	"tee": true, "cat": true, "rev": true, "tr": true,
}

// pipedSecretReachesLog reports whether a secret printed just before the pipe
// at pipeStart still reaches the job log: the pipeline's terminal stage is a
// logEncoders command and its stdout is not redirected to a file. s is the
// single-quote-masked line; separators is its maskShellQuotes form, so a pipe,
// redirect or terminator inside a double-quoted argument is not read as shell
// structure.
func pipedSecretReachesLog(s, separators string, pipeStart int) bool {
	end := len(separators)
	for i := pipeStart + 1; i < len(separators); i++ {
		c := separators[i]
		// A command terminator ends the pipeline; `&&`, `||` and `&` all begin
		// with a character that is not part of a pipe stage.
		if c == ';' || c == '\n' || c == '&' || c == ')' ||
			(c == '|' && i+1 < len(separators) && separators[i+1] == '|') {
			end = i
			break
		}
	}
	// Output redirected away from the log (`>` to a file or /dev/null) is
	// GL014's territory, not a log leak.
	if strings.ContainsRune(separators[pipeStart:end], '>') {
		return false
	}
	last := strings.LastIndexByte(separators[pipeStart:end], '|') + pipeStart
	return logEncoders[commandName(commandWords(s[last+1:end]))]
}

// shortSubstring reports whether rest, the text after a braced variable name,
// is a substring expansion :offset:length} whose length is a literal from 0
// to 16. The offset may be empty (${NAME::8}). A negative or computed length,
// or a missing one (${NAME:8} prints to the end), does not count.
func shortSubstring(rest string) bool {
	if !strings.HasPrefix(rest, ":") {
		return false
	}
	body, _, closed := strings.Cut(rest[1:], "}")
	if !closed {
		return false
	}
	offset, length, ok := strings.Cut(body, ":")
	if !ok || strings.Contains(length, ":") {
		return false
	}
	offset, length = strings.TrimSpace(offset), strings.TrimSpace(length)
	if offset != "" {
		if _, err := strconv.Atoi(offset); err != nil {
			return false
		}
	}
	if length == "" || length[0] < '0' || length[0] > '9' {
		return false
	}
	n, err := strconv.Atoi(length)
	return err == nil && n <= 16
}

// informationRedirected checks for a direct information-stream file redirect,
// ignoring operators inside quoted or backtick-escaped argument text.
func informationRedirected(seg string) bool {
	var quote byte
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		switch {
		case c == '`':
			i++
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case (c == '6' || c == '*') && (i == 0 || isShellSpace(seg[i-1])):
			if gl021InfoFileRedirectRe.MatchString(seg[i:]) {
				return true
			}
		}
	}
	return false
}

// isSecretName reports whether a variable name looks like it holds a secret
// value: it carries a secret indicator and doesn't end in a segment such as
// _ID or _URL that names something else.
func isSecretName(name string) bool {
	return secretNameRe.MatchString(name) && !nonSecretSuffixRe.MatchString(name) && !nonSecretPredefined[name]
}

// nonSecretPredefined are predefined variables whose names look secret but
// whose values are not: CI_RUNNER_SHORT_TOKEN is documented as an identifier.
var nonSecretPredefined = map[string]bool{"CI_RUNNER_SHORT_TOKEN": true}

// predefinedSecrets are GitLab's predefined credentials, which every job gets
// anyway.
var predefinedSecrets = map[string]bool{
	"CI_JOB_TOKEN": true, "CI_REGISTRY_PASSWORD": true, "CI_DEPENDENCY_PROXY_PASSWORD": true,
	"CI_DEPLOY_PASSWORD": true, "CI_JOB_JWT": true, "CI_JOB_JWT_V1": true, "CI_JOB_JWT_V2": true,
}

// isPredefinedVar reports whether name is a predefined variable that every
// job gets anyway: a predefined credential, or a CI_/GITLAB_ name that doesn't
// look secret. A secret-looking CI_ name such as CI_API_TOKEN is a project
// setting, not predefined.
func isPredefinedVar(name string) bool {
	if predefinedSecrets[name] {
		return true
	}
	return (strings.HasPrefix(name, "CI_") || strings.HasPrefix(name, "GITLAB_")) && !secretNameRe.MatchString(name)
}

// segmentPrintCommand returns the print command at the start of a segment,
// canonicalizing PowerShell command names. It skips leading env assignments and
// group/keyword openers, then checks the first real token — so an `echo` that
// only appears inside a quoted argument (the secret is not actually printed)
// does not count.
func segmentPrintCommand(segHead string) string {
	// Quoted placeholders preserve redirect targets, but command recognition
	// keeps the earlier behavior of treating single-quoted spans as blanks.
	segHead = strings.ReplaceAll(segHead, "''", " ")
	words := unwrapCommand(strings.Fields(segHead))
	if len(words) == 0 {
		return ""
	}
	tok := words[0]
	if tok == "echo" || tok == "printf" || tok == "print" {
		return tok
	}
	command := strings.ToLower(tok)
	switch command {
	case "write-host", "write-output", "write-information", "write":
		return command
	}
	return ""
}

// isShellSep reports whether b separates shell commands (pipeline, list, or
// substitution boundaries). Note `{`/`}` are intentionally excluded: they close
// `${VAR}` brace expansions far more often than they group commands, and
// treating them as separators truncates a segment mid-variable (hiding a later
// redirect or pipe).
func isShellSep(b byte) bool {
	switch b {
	case '|', '&', ';', '(', ')':
		return true
	}
	return false
}

// varRefText is a reference as the message shows it: ${NAME:0:4} matches as
// "${NAME", so the brace is closed (#977).
func varRefText(ref string) string {
	if strings.HasPrefix(ref, "${") && !strings.HasSuffix(ref, "}") {
		return ref + "}"
	}
	return ref
}

// groupOutputDiverted reports whether the position pos of a script line is
// inside a `{ …; }` group or a `( … )` subshell whose output goes to a file
// or a pipe: `{ echo …; } >> .npmrc`, `( echo … ) | ssh-add -`. Brackets of
// ${…}, $(…) and quoted text don't count.
func groupOutputDiverted(s string, pos int) bool {
	type open struct {
		at    int
		brace bool
	}
	var stack []open
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else if c == '\\' && quote == '"' {
				i++
			}
		case c == '\\':
			i++
		case c == '\'' || c == '"':
			quote = c
		case (c == '{' || c == '(') && i > 0 && s[i-1] == '$':
			stack = append(stack, open{at: -1, brace: c == '{'})
		case c == '{' || c == '(':
			stack = append(stack, open{at: i, brace: c == '{'})
		case (c == '}' || c == ')') && len(stack) > 0:
			o := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if o.at < 0 || o.at > pos || i < pos {
				continue
			}
			rest := strings.TrimLeft(s[i+1:], " \t")
			if strings.HasPrefix(rest, ">") || strings.HasPrefix(rest, "1>") || strings.HasPrefix(rest, "&>") ||
				(strings.HasPrefix(rest, "|") && !strings.HasPrefix(rest, "||")) {
				return true
			}
		}
	}
	return false
}

// childPrintScript returns the script a command hands to a new shell or to
// eval. Unlike childShellScript this includes eval, su -c, and shells started
// with -o pipefail: those still expand and may print a secret (#1356).
func childPrintScript(text string) (string, bool) {
	words := commandWords(text)
	if len(words) == 0 {
		return "", false
	}
	if commandName(words) == "eval" && len(words) > 1 {
		return strings.Join(words[1:], " "), true
	}
	if commandName(words) == "ssh" {
		// A single-quoted remote command is not expanded by the job shell, so
		// $DEPLOY_TOKEN in ssh host 'echo $DEPLOY_TOKEN' is the remote
		// environment, not the CI secret.
		if sshRemoteCommandSingleQuoted(text) {
			return "", false
		}
		i := 1
		for ; i < len(words) && len(words[i]) > 1 && words[i][0] == '-'; i++ {
			if len(words[i]) == 2 && strings.IndexByte(sshValueOptions, words[i][1]) >= 0 {
				i++
			}
		}
		if i+1 < len(words) {
			return strings.Join(words[i+1:], " "), true
		}
		return "", false
	}
	for i, w := range words {
		name := commandName([]string{w})
		if !posixShells[name] && name != "su" {
			continue
		}
		for j := i + 1; j < len(words); j++ {
			opt := words[j]
			switch {
			case opt == "-c" || opt == "--command":
				if j+1 < len(words) {
					return words[j+1], true
				}
				return "", false
			case strings.HasPrefix(opt, "--"):
				// --login and long options are not a -c flag.
			case strings.HasPrefix(opt, "-") && strings.ContainsRune(opt[1:], 'c'):
				if j+1 < len(words) {
					return words[j+1], true
				}
				return "", false
			case opt == "-o":
				j++
			}
		}
	}
	return "", false
}

// childShellOutputDiverted reports whether a child-shell command's output is
// redirected, piped, or captured, so a print inside the script does not reach
// the job log.
func childShellOutputDiverted(line string) bool {
	s := singleQuotedRe.ReplaceAllString(line, "''")
	masked := maskShellQuotes(s)
	if strings.Contains(masked, ">") || strings.Contains(masked, "|") {
		return true
	}
	if strings.Contains(masked, "$(") || strings.Contains(masked, "<(") {
		return true
	}
	// Approximate the command start; a wrapping { …; } or ( … ) group with
	// diverted output is the same as for a direct print.
	return groupOutputDiverted(s, len(s)/2)
}

// sshRemoteCommandSingleQuoted reports whether the remote command of an ssh
// invocation is a single-quoted word in the job script.
func sshRemoteCommandSingleQuoted(text string) bool {
	i := 0
	found := false
	for i < len(text) {
		word, quote, j := nextRawShellWord(text, i)
		if word == "" {
			return false
		}
		if commandName([]string{word}) == "ssh" && quote == 0 {
			i = j
			found = true
			break
		}
		i = j
	}
	if !found {
		return false
	}
	sawHost := false
	for i < len(text) {
		word, quote, j := nextRawShellWord(text, i)
		if word == "" {
			return false
		}
		if !sawHost {
			if strings.HasPrefix(word, "-") && quote == 0 {
				if len(word) == 2 && strings.IndexByte(sshValueOptions, word[1]) >= 0 {
					_, _, j = nextRawShellWord(text, j)
				}
				i = j
				continue
			}
			sawHost = true
			i = j
			continue
		}
		return quote == '\''
	}
	return false
}

// nextRawShellWord returns the next shell word in s starting at i, the quote
// that wrapped it (' or " or 0), and the index after the word.
func nextRawShellWord(s string, i int) (word string, quote byte, j int) {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	if i >= len(s) {
		return "", 0, i
	}
	if s[i] == '\'' || s[i] == '"' {
		q := s[i]
		i++
		start := i
		for i < len(s) && s[i] != q {
			if s[i] == '\\' && q == '"' && i+1 < len(s) {
				i++
			}
			i++
		}
		word = s[start:i]
		if i < len(s) {
			i++
		}
		return word, q, i
	}
	start := i
	for i < len(s) && s[i] != ' ' && s[i] != '\t' {
		i++
	}
	return s[start:i], 0, i
}
