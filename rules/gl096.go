// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type gl096 struct{}

// GL096 flags a script command that connects to a cryptocurrency mining pool:
// a `stratum+tcp://`, `stratum+ssl://` or `stratum+tls://` URL, or a known
// mining-pool host. Running a miner on the project's runners is CI-minute
// cryptojacking, the abuse that follows a leaked CI token or a malicious fork
// pipeline (#1437). Only the pool connection is reported: building, cloning or
// pulling an image of a miner (`git clone .../xmrig.git`, `image: strm/xmrig`)
// is legitimate, and the bare tool name never triggers the rule.
var GL096 = &gl096{}

func (r *gl096) ID() string { return "GL096" }

// gl096StratumRe matches a Stratum mining-protocol URL, the scheme every
// mainstream miner uses to reach a pool and nothing else uses, up to the end
// of the word so the finding names the pool.
var gl096StratumRe = mustCompilePrefiltered(`(?i)stratum\+(?:tcp|ssl|tls)://[^\s"'` + "`" + `;|&)]*`)

// gl096PoolNames are mining pools whose domains have no use in a pipeline other
// than mining, each matched under the top-level domains below. A host matches
// as the domain itself or any subdomain of it (pool.supportxmr.com,
// gulf.moneroocean.stream), never as part of a longer domain.
var (
	gl096PoolNames = []string{"supportxmr", "minexmr", "moneroocean", "nanopool", "hashvault", "c3pool", "herominers", "2miners", "unmineable"}
	gl096PoolTLDs  = []string{"com", "org", "net", "stream", "pro"}
)

// gl096PoolHost returns the mining-pool host text names (subdomains included),
// or "".
// The domain must end at a non-host byte (a port colon, a slash, a quote, a
// space or the end) and start at a non-host byte or a subdomain dot, so
// `supportxmr.com.example.org` and `notsupportxmr.com` are not matches.
func gl096PoolHost(text string) string {
	lower := strings.ToLower(text)
	for _, name := range gl096PoolNames {
		for i := 0; ; {
			j := strings.Index(lower[i:], name+".")
			if j < 0 {
				break
			}
			j += i
			i = j + len(name)
			if j > 0 && lower[j-1] != '.' && gl095IsHostByte(lower[j-1]) {
				continue
			}
			for _, tld := range gl096PoolTLDs {
				end := j + len(name) + 1 + len(tld)
				if !strings.HasPrefix(lower[j+len(name)+1:], tld) {
					continue
				}
				if end < len(lower) && gl095IsHostByte(lower[end]) {
					continue
				}
				start := j // report the whole host, subdomains included
				for start > 0 && gl095IsHostByte(lower[start-1]) {
					start--
				}
				return text[start:end]
			}
		}
	}
	return ""
}

// gl096Mentions is a cheap case-insensitive prefilter: a line with neither the
// Stratum scheme nor a pool name cannot match, so the shell parse is skipped.
func gl096Mentions(v string) bool {
	lower := strings.ToLower(v)
	if strings.Contains(lower, "stratum+") {
		return true
	}
	for _, name := range gl096PoolNames {
		if strings.Contains(lower, name) {
			return true
		}
	}
	return false
}

const gl096Msg = "script connects to a cryptocurrency mining pool (%s) — running a miner on the project's " +
	"runners is CI-minute cryptojacking, typically pushed with a leaked CI token or through a fork pipeline; " +
	"remove the job, then rotate the tokens that could push it and review recent pipeline changes"

// gl096Assess returns the pool connection on a script line, or "". It walks the
// simple commands so a pool URL that is only printed (echo/printf) is not read
// as a connection; comments are already blanked by the script walk.
func gl096Assess(v string) string {
	for _, cmd := range shellCommands(v) {
		if printsOnly(cmd, commandWords(cmd.text)) {
			continue
		}
		if m := gl096StratumRe.FindString(cmd.text); m != "" {
			return m
		}
		if m := gl096PoolHost(cmd.text); m != "" {
			return m
		}
	}
	return ""
}

func (r *gl096) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(line *yaml.Node, file, job string) {
		v := line.Value
		if !gl096Mentions(v) {
			return
		}
		trigger := gl096Assess(v)
		if trigger == "" {
			return
		}
		off := 0
		if i := strings.Index(v, trigger); i >= 0 {
			off = i
		}
		ln, col := scriptMatchPos(line, off)
		findings = append(findings, finding.Finding{
			RuleID:   "GL096",
			Severity: finding.Error,
			Job:      job,
			Message:  strings.Replace(gl096Msg, "%s", trigger, 1),
			File:     file,
			Line:     ln,
			Col:      col,
		})
	})
	return findings
}
