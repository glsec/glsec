// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl094 struct{}

// GL094 flags reading an SSH private key only to stage it for exfiltration:
// piping it into an encoder, archiving it, or copying it off to another path.
// A bare `cat ~/.ssh/id_rsa` is low signal (it can be debugging), and writing a
// key into place (echo "$KEY" > ~/.ssh/id_rsa), using it (ssh-add, chmod), or
// generating one (ssh-keygen) are all left to GL032 or ignored. The dangerous
// shape is read → encode / archive / copy-off (#1365).
var GL094 = &gl094{}

func (r *gl094) ID() string { return "GL094" }

var (
	// gl094KeyFileRe matches a shell word whose basename is a canonical SSH
	// private key. The `$` anchor keeps id_rsa.pub (a public key) out.
	gl094KeyFileRe = mustCompilePrefiltered(`(?:^|/)id_(?:rsa|dsa|ecdsa|ed25519)$`)
	// gl094SSHDirRe matches the .ssh directory itself (tar/cp of the whole dir),
	// not a single non-key file under it such as ~/.ssh/known_hosts.
	gl094SSHDirRe = mustCompilePrefiltered(`(?:^|/)\.ssh/?$`)
)

// gl094Encoders re-encode their input, the tell of staging a key to slip past a
// reviewer or a masker. gl094Archivers bundle it; gl094CopyOff move it off.
var (
	gl094Encoders = map[string]bool{
		"base64": true, "base32": true, "base16": true, "basenc": true,
		"xxd": true, "od": true, "hexdump": true, "uuencode": true,
	}
	gl094Archivers = map[string]bool{
		"tar": true, "zip": true, "gzip": true, "bzip2": true, "xz": true,
		"zstd": true, "7z": true, "7za": true, "rar": true, "cpio": true,
	}
	gl094CopyOff = map[string]bool{"cp": true, "mv": true, "install": true}
)

// gl094MentionsKey is a cheap substring prefilter for the Check loop.
func gl094MentionsKey(v string) bool {
	return strings.Contains(v, ".ssh") ||
		strings.Contains(v, "id_rsa") || strings.Contains(v, "id_dsa") ||
		strings.Contains(v, "id_ecdsa") || strings.Contains(v, "id_ed25519")
}

func gl094IsKeyArg(word string) bool {
	w := strings.Trim(word, `"'`)
	return gl094KeyFileRe.MatchString(w) || gl094SSHDirRe.MatchString(w)
}

// gl094Args returns a command's operands past its name, dropping option flags.
func gl094Args(words []string) []string {
	var args []string
	for _, w := range words[1:] {
		if strings.HasPrefix(w, "-") {
			continue
		}
		args = append(args, w)
	}
	return args
}

func (r *gl094) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		v := line.Value
		// Most script lines mention no key at all. Skip the shell parse unless a
		// key filename or the .ssh directory is present (a cheap prefilter, so
		// the rule costs almost nothing on ordinary lines).
		if !gl094MentionsKey(v) {
			return
		}
		if strings.HasPrefix(strings.TrimSpace(v), "#") {
			return
		}
		cmds := shellCommands(v)
		reason := gl094ExfilReason(cmds)
		if reason == "" {
			return
		}
		ln, col := scriptMatchPos(line, 0)
		findings = append(findings, finding.Finding{
			RuleID:   "GL094",
			Severity: finding.Error,
			Job:      job,
			Message: "SSH private key read and " + reason +
				" — reading a private key only to encode, archive, or copy it off is credential exfiltration; remove this",
			File: file,
			Line: ln,
			Col:  col,
		})
	})
	return findings
}

// gl094IsEncoder reports whether a command runs an encoder in its encode
// direction. `base64 -d` / `base32 -d` decode, which is how a CI job writes a
// deploy key into place (echo "$KEY_B64" | base64 -d > ~/.ssh/id_rsa) — not a
// read for exfil (#1398 false positive).
func gl094IsEncoder(w []string) bool {
	if !gl094Encoders[commandName(w)] {
		return false
	}
	_, decodes := payloadDecoder(w)
	return !decodes
}

// gl094KeyOperand reports whether a command reads a key path as one of its own
// operands. A key path that is a redirect target (`> ~/.ssh/id_rsa`) is
// written, not read, so it does not count.
func gl094KeyOperand(w []string) bool {
	args := gl094Args(w)
	for i, a := range args {
		if gl094IsKeyArg(a) && (i == 0 || !isRedirectWord(args[i-1])) {
			return true
		}
	}
	return false
}

// gl094EmitsKey reports whether a command streams a private key's own bytes to
// stdout, so a downstream encoder would re-encode the key itself. ssh-keygen is
// excluded: `ssh-keygen -y -f id_rsa` derives and prints the PUBLIC key, not
// private-key content, so piping it into an encoder is not exfiltration (#1414).
func gl094EmitsKey(w []string) bool {
	if commandName(w) == "ssh-keygen" {
		return false
	}
	return gl094KeyOperand(w)
}

// gl094KeyReachesEncoder reports whether a private key is read into an encoder
// within a single connected pipeline: the encoder reads the key as its own file
// operand (base64 id_rsa), or an earlier stage emits the key's bytes into an
// encoder stage downstream (cat id_rsa | base64).
func gl094KeyReachesEncoder(pipe []shellCommand) bool {
	for pos, c := range pipe {
		w := commandWords(c.text)
		if len(w) == 0 {
			continue
		}
		if gl094IsEncoder(w) && gl094KeyOperand(w) {
			return true
		}
		if gl094EmitsKey(w) {
			for _, later := range pipe[pos+1:] {
				if lw := commandWords(later.text); len(lw) > 0 && gl094IsEncoder(lw) {
					return true
				}
			}
		}
	}
	return false
}

// gl094ExfilReason returns why a script line stages a private key for
// exfiltration, or "" if it does not.
func gl094ExfilReason(cmds []shellCommand) string {
	// A private key read into an encoder, either as the encoder's own file
	// operand (base64 id_rsa) or along one connected pipeline (cat id_rsa |
	// base64). Commands separated by ;, &&, ||, or a newline run in different
	// pipelines and must not be combined: a key touched on one line and an
	// unrelated encoder on another is not exfiltration (#1414).
	for i := 0; i < len(cmds); {
		j := i
		for j < len(cmds)-1 && cmds[j].piped {
			j++
		}
		if gl094KeyReachesEncoder(cmds[i : j+1]) {
			return "piped into an encoder"
		}
		i = j + 1
	}
	// Archived, or copied/moved off to another path.
	for _, c := range cmds {
		w := commandWords(c.text)
		if len(w) == 0 {
			continue
		}
		name := commandName(w)
		args := gl094Args(w)
		if gl094Archivers[name] {
			for _, a := range args {
				if gl094IsKeyArg(a) {
					return "archived"
				}
			}
		}
		// cp/mv SOURCE… DEST: a key among the sources is copied off. A key moved
		// or copied INTO ~/.ssh (or onto another key path) installs it for use,
		// not an exfiltration — the destination decides (#1398 false positive).
		if gl094CopyOff[name] && len(args) >= 2 {
			dest := strings.Trim(args[len(args)-1], `"'`)
			if gl094IsKeyArg(dest) || strings.Contains(dest, ".ssh") {
				continue
			}
			for _, a := range args[:len(args)-1] {
				if gl094IsKeyArg(a) {
					return "copied to another location"
				}
			}
		}
	}
	return ""
}
