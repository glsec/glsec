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

// gl094ExfilReason returns why a script line stages a private key for
// exfiltration, or "" if it does not.
func gl094ExfilReason(cmds []shellCommand) string {
	// A key whose output is re-encoded, in one command (base64 id_rsa) or along
	// a pipeline (cat id_rsa | base64).
	encoder, keyArg := false, false
	for _, c := range cmds {
		w := commandWords(c.text)
		if len(w) == 0 {
			continue
		}
		if gl094Encoders[commandName(w)] {
			encoder = true
		}
		for _, a := range gl094Args(w) {
			if gl094IsKeyArg(a) {
				keyArg = true
			}
		}
	}
	if encoder && keyArg {
		return "piped into an encoder"
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
		// cp/mv SOURCE… DEST: a key among the sources is copied off; a key only
		// as the destination is a write into place (GL032's side), not a read.
		if gl094CopyOff[name] && len(args) >= 2 {
			for _, a := range args[:len(args)-1] {
				if gl094IsKeyArg(a) {
					return "copied to another location"
				}
			}
		}
	}
	return ""
}
