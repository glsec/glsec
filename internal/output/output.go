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
		return writeSARIF(w, findings)
	default:
		return writeText(w, findings)
	}
}

func writeText(w io.Writer, findings []finding.Finding) error {
	for _, f := range findings {
		_, err := fmt.Fprintf(w, "%-6s %s:%d  %s  %s\n",
			strings.ToUpper(string(f.Severity)),
			f.File, f.Line,
			f.RuleID,
			f.Message,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

type jsonFinding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
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
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string `json:"name"`
	InformationURI string `json:"informationUri"`
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

func writeSARIF(w io.Writer, findings []finding.Finding) error {
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
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "glsec",
				InformationURI: "https://github.com/glsec/glsec",
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
