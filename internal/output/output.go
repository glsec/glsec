package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/glsec/glsec/internal/finding"
)

type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
	FormatSARIF Format = "sarif"
)

func ParseFormat(s string) (Format, bool) {
	switch Format(s) {
	case FormatText, FormatJSON, FormatSARIF:
		return Format(s), true
	default:
		return "", false
	}
}

func Write(w io.Writer, format Format, findings []finding.Finding) error {
	switch format {
	case FormatJSON:
		return writeJSON(w, findings)
	case FormatSARIF:
		return writeSARIF(w, findings, nil, nil)
	default:
		return writeText(w, findings)
	}
}

func writeText(w io.Writer, findings []finding.Finding) error {
	for _, f := range findings {
		var err error
		if f.Job != "" {
			_, err = fmt.Fprintf(w, "%-6s %s:%d  %s  [%s]  %s\n",
				strings.ToUpper(string(f.Severity)),
				f.File, f.Line,
				f.RuleID,
				f.Job,
				f.Message,
			)
		} else {
			_, err = fmt.Fprintf(w, "%-6s %s:%d  %s  %s\n",
				strings.ToUpper(string(f.Severity)),
				f.File, f.Line,
				f.RuleID,
				f.Message,
			)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

type jsonFinding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Job      string `json:"job,omitempty"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Message  string `json:"message"`
}

type jsonOutput struct {
	Findings []jsonFinding `json:"findings"`
}

func writeJSON(w io.Writer, findings []finding.Finding) error {
	out := jsonOutput{Findings: make([]jsonFinding, 0, len(findings))}
	for _, f := range findings {
		out.Findings = append(out.Findings, jsonFinding{
			Rule:     f.RuleID,
			Severity: string(f.Severity),
			Job:      f.Job,
			File:     f.File,
			Line:     f.Line,
			Message:  f.Message,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// SARIF 2.1.0 types — minimal subset for Code Scanning / GitLab SAST.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool        `json:"tool"`
	Taxonomies []sarifTaxonomy  `json:"taxonomies,omitempty"`
	Results    []sarifResult    `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string       `json:"name"`
	InformationURI string       `json:"informationUri"`
	Rules          []sarifRule  `json:"rules,omitempty"`
}

type sarifRule struct {
	ID            string                  `json:"id"`
	Relationships []sarifRelationship     `json:"relationships,omitempty"`
}

type sarifRelationship struct {
	Target sarifRelationshipTarget `json:"target"`
	Kinds  []string                `json:"kinds"`
}

type sarifRelationshipTarget struct {
	ID            string                    `json:"id"`
	ToolComponent sarifToolComponentRef     `json:"toolComponent"`
}

type sarifToolComponentRef struct {
	Name string `json:"name"`
}

type sarifTaxonomy struct {
	Name             string      `json:"name"`
	Version          string      `json:"version"`
	Organization     string      `json:"organization"`
	Taxa             []sarifTaxon `json:"taxa"`
}

type sarifTaxon struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func severityToSARIFLevel(s finding.Severity) string {
	switch s {
	case finding.Error:
		return "error"
	case finding.Warn:
		return "warning"
	default:
		return "note"
	}
}

// WriteSARIF writes SARIF output enriched with CWE metadata.
// cweID maps a rule ID to its CWE identifier (e.g. "CWE-798").
// cweName maps a CWE identifier to its human-readable name.
// Pass nil for either to omit CWE data.
func WriteSARIF(w io.Writer, findings []finding.Finding, cweID func(string) string, cweName func(string) string) error {
	return writeSARIF(w, findings, cweID, cweName)
}

func writeSARIF(w io.Writer, findings []finding.Finding, cweID func(string) string, cweName func(string) string) error {
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		results = append(results, sarifResult{
			RuleID:  f.RuleID,
			Level:   severityToSARIFLevel(f.Severity),
			Message: sarifMessage{Text: f.Message},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.File},
					Region:           sarifRegion{StartLine: f.Line},
				},
			}},
		})
	}

	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           "glsec",
			InformationURI: "https://github.com/glsec/glsec",
		}},
		Results: results,
	}

	if cweID != nil && cweName != nil {
		seenRules := map[string]bool{}
		seenCWEs := map[string]bool{}
		for _, f := range findings {
			if seenRules[f.RuleID] {
				continue
			}
			seenRules[f.RuleID] = true
			cwe := cweID(f.RuleID)
			if cwe == "" {
				continue
			}
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
				ID: f.RuleID,
				Relationships: []sarifRelationship{{
					Target: sarifRelationshipTarget{
						ID:            cwe,
						ToolComponent: sarifToolComponentRef{Name: "CWE"},
					},
					Kinds: []string{"superset"},
				}},
			})
			seenCWEs[cwe] = true
		}
		if len(seenCWEs) > 0 {
			taxa := make([]sarifTaxon, 0, len(seenCWEs))
			for cwe := range seenCWEs {
				taxa = append(taxa, sarifTaxon{ID: cwe, Name: cweName(cwe)})
			}
			run.Taxonomies = []sarifTaxonomy{{
				Name:         "CWE",
				Version:      "4.14",
				Organization: "MITRE",
				Taxa:         taxa,
			}}
		}
	}

	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
