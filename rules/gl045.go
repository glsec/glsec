package rules

import (
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl045 struct{}

var GL045 = &gl045{}

func (r *gl045) ID() string { return "GL045" }

// releaseKeywords identifies job and stage names that indicate a release or publish step.
var releaseKeywords = []string{"release", "publish", "deploy", "push", "upload", "dist"}

// releasePushRe matches script lines that push artifacts to a registry or package index.
var releasePushRe = regexp.MustCompile(
	`\bdocker\s+push\b` +
		`|\bcrane\s+push\b` +
		`|\bhelm\s+push\b` +
		`|\btwine\s+upload\b` +
		`|\bcargo\s+publish\b` +
		`|\bnpm\s+publish\b` +
		`|\bgoreleaser\s+release\b`,
)

// releaseSigningRe matches script lines that cryptographically sign an artifact.
var releaseSigningRe = regexp.MustCompile(
	`\bcosign\s+sign\b` +
		`|\bgpg\b.*--detach-sign\b` +
		`|\bgpg\b.*\s-b\b` +
		`|\bnotation\s+sign\b` +
		`|\bslsa-verifier\b`,
)

func (r *gl045) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if !isReleaseJob(name.Value, job) {
			return
		}

		lines := collectJobScriptLines(job)
		if len(lines) == 0 {
			return
		}

		var pushLine *yaml.Node
		hasSigning := false

		for _, line := range lines {
			if line.Kind != yaml.ScalarNode {
				continue
			}
			if pushLine == nil && releasePushRe.MatchString(line.Value) {
				pushLine = line
			}
			if releaseSigningRe.MatchString(line.Value) {
				hasSigning = true
			}
		}

		if pushLine == nil || hasSigning {
			return
		}

		findings = append(findings, finding.Finding{
			RuleID:   "GL045",
			Severity: finding.Warn,
			Job:      name.Value,
			Message:  "release job pushes artifacts without a signing step — consumers cannot verify artifact integrity; add cosign, gpg --detach-sign, or notation sign",
			File:     file,
			Line:     pushLine.Line,
			Col:      pushLine.Column,
		})
	})

	return findings
}

func isReleaseJob(jobName string, job *yaml.Node) bool {
	lower := strings.ToLower(jobName)
	for _, kw := range releaseKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	if stageNode := parser.FindKey(job, "stage"); stageNode != nil && stageNode.Kind == yaml.ScalarNode {
		lowerStage := strings.ToLower(stageNode.Value)
		for _, kw := range releaseKeywords {
			if strings.Contains(lowerStage, kw) {
				return true
			}
		}
	}
	return false
}

func collectJobScriptLines(job *yaml.Node) []*yaml.Node {
	var lines []*yaml.Node
	for _, key := range []string{"before_script", "script", "after_script"} {
		node := parser.FindKey(job, key)
		if node == nil || node.Kind != yaml.SequenceNode {
			continue
		}
		lines = append(lines, node.Content...)
	}
	return lines
}
