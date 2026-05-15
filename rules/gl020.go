package rules

import (
	"regexp"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl020 struct{}

var GL020 = &gl020{}

func (r *gl020) ID() string { return "GL020" }

var (
	// downloadSavesRe matches curl/wget invocations that save to disk rather than piping directly.
	// Handles -O, -o, --output, and combined flag clusters like -sSLO.
	downloadSavesRe = regexp.MustCompile(`\b(?:curl\b[^|]*(?:-[a-zA-Z]*[oO]\b|--output\b)|wget\b)`)

	// checksumRe matches checksum/signature verification commands.
	checksumRe = regexp.MustCompile(`\b(?:sha(?:256|512|1|224|384)sum|shasum|md5sum|gpg\s+--verify|cosign\s+verify|openssl\s+dgst)\b`)
)

func (r *gl020) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		lines := collectScriptLines(job)
		if len(lines) == 0 {
			return
		}

		// Find the first download-to-disk line.
		var downloadLine *yaml.Node
		for _, l := range lines {
			if downloadSavesRe.MatchString(l.Value) && !isDownloadExecute(l.Value) {
				downloadLine = l
				break
			}
		}
		if downloadLine == nil {
			return
		}

		// If any line in the job has a checksum command, the job is considered safe.
		for _, l := range lines {
			if checksumRe.MatchString(l.Value) {
				return
			}
		}

		findings = append(findings, finding.Finding{
			RuleID:   "GL020",
			Severity: finding.Warn,
			Job:      name.Value,
			Message:  "job downloads a file with curl/wget but no checksum verification (sha256sum, gpg --verify, etc.) found in script",
			File:     file,
			Line:     downloadLine.Line,
			Col:      downloadLine.Column,
		})
	})

	return findings
}

// collectScriptLines returns all scalar script lines across script/before_script/after_script.
func collectScriptLines(job *yaml.Node) []*yaml.Node {
	var lines []*yaml.Node
	for _, key := range []string{"before_script", "script", "after_script"} {
		node := parser.FindKey(job, key)
		if node == nil || node.Kind != yaml.SequenceNode {
			continue
		}
		for _, item := range node.Content {
			if item.Kind == yaml.ScalarNode {
				lines = append(lines, item)
			}
		}
	}
	return lines
}
