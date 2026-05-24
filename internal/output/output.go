package output

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/glsec/glsec/internal/color"
	"github.com/glsec/glsec/internal/finding"
)

type Format string

const (
	FormatText        Format = "text"
	FormatJSON        Format = "json"
	FormatSARIF       Format = "sarif"
	FormatCodeClimate Format = "codeclimate"
)

func ParseFormat(s string) (Format, bool) {
	switch Format(s) {
	case FormatText, FormatJSON, FormatSARIF, FormatCodeClimate:
		return Format(s), true
	default:
		return "", false
	}
}

func Write(w io.Writer, format Format, findings []finding.Finding, jobCount int, colorEnabled bool) error {
	switch format {
	case FormatJSON:
		return writeJSON(w, findings, nil, nil)
	case FormatSARIF:
		return writeSARIF(w, findings, nil, nil, nil, nil, nil, nil)
	case FormatCodeClimate:
		return writeCodeClimate(w, findings)
	default:
		return writeText(w, findings, jobCount, colorEnabled)
	}
}

func writeText(w io.Writer, findings []finding.Finding, jobCount int, col bool) error {
	for _, f := range findings {
		sev := strings.ToUpper(string(f.Severity))
		switch f.Severity {
		case finding.Error:
			sev = color.Red(sev, col)
		case finding.Warn:
			sev = color.Yellow(sev, col)
		}
		ruleID := color.Bold(f.RuleID, col)
		location := color.Bold(fmt.Sprintf("%s:%d", f.File, f.Line), col)

		var err error
		if f.Job != "" {
			_, err = fmt.Fprintf(w, "%-6s %s  %s  [%s]  %s\n",
				sev, location, ruleID, f.Job, f.Message,
			)
		} else {
			_, err = fmt.Fprintf(w, "%-6s %s  %s  %s\n",
				sev, location, ruleID, f.Message,
			)
		}
		if err != nil {
			return err
		}
	}
	if len(findings) == 0 {
		_, err := fmt.Fprintf(w, "Scanned %d jobs, 0 issues found.\n", jobCount)
		return err
	}
	return nil
}

type jsonFinding struct {
	Rule     string   `json:"rule"`
	Severity string   `json:"severity"`
	Job      string   `json:"job,omitempty"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Message  string   `json:"message"`
	OWASP    []string `json:"owasp,omitempty"`
	ASVS     []string `json:"asvs,omitempty"`
}

type jsonOutput struct {
	Findings []jsonFinding `json:"findings"`
}

// WriteJSON writes findings as JSON. owasp and asvs, if non-nil, are called
// per finding to populate the "owasp" and "asvs" fields.
func WriteJSON(w io.Writer, findings []finding.Finding, owasp, asvs func(string) []string) error {
	return writeJSON(w, findings, owasp, asvs)
}

func writeJSON(w io.Writer, findings []finding.Finding, owasp, asvs func(string) []string) error {
	out := jsonOutput{Findings: make([]jsonFinding, 0, len(findings))}
	for _, f := range findings {
		jf := jsonFinding{
			Rule:     f.RuleID,
			Severity: string(f.Severity),
			Job:      f.Job,
			File:     f.File,
			Line:     f.Line,
			Message:  f.Message,
		}
		if owasp != nil {
			jf.OWASP = owasp(f.RuleID)
		}
		if asvs != nil {
			jf.ASVS = asvs(f.RuleID)
		}
		out.Findings = append(out.Findings, jf)
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
	Tool       sarifTool       `json:"tool"`
	Taxonomies []sarifTaxonomy `json:"taxonomies,omitempty"`
	Results    []sarifResult   `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID            string              `json:"id"`
	Relationships []sarifRelationship `json:"relationships,omitempty"`
}

type sarifRelationship struct {
	Target sarifRelationshipTarget `json:"target"`
	Kinds  []string                `json:"kinds"`
}

type sarifRelationshipTarget struct {
	ID            string                `json:"id"`
	ToolComponent sarifToolComponentRef `json:"toolComponent"`
}

type sarifToolComponentRef struct {
	Name string `json:"name"`
}

type sarifTaxonomy struct {
	Name         string       `json:"name"`
	Version      string       `json:"version"`
	Organization string       `json:"organization"`
	Taxa         []sarifTaxon `json:"taxa"`
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

// WriteSARIF writes SARIF output enriched with CWE and OWASP metadata.
// cweID maps a rule ID to its CWE identifier (e.g. "CWE-798").
// cweName maps a CWE identifier to its human-readable name.
// owasp maps a rule ID to its OWASP CI/CD Security Risks categories.
// owaspName maps an OWASP category ID to its human-readable name.
// Pass nil for any parameter to omit that taxonomy.
func WriteSARIF(w io.Writer, findings []finding.Finding,
	cweID func(string) string, cweName func(string) string,
	owasp func(string) []string, owaspName func(string) string,
	asvs func(string) []string, asvsName func(string) string,
) error {
	return writeSARIF(w, findings, cweID, cweName, owasp, owaspName, asvs, asvsName)
}

func writeSARIF(w io.Writer, findings []finding.Finding,
	cweID func(string) string, cweName func(string) string,
	owasp func(string) []string, owaspName func(string) string,
	asvs func(string) []string, asvsName func(string) string,
) error {
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

	seenRules := map[string]bool{}
	seenCWEs := map[string]bool{}
	seenOWASP := map[string]bool{}
	seenASVS := map[string]bool{}

	for _, f := range findings {
		if seenRules[f.RuleID] {
			continue
		}
		seenRules[f.RuleID] = true

		var rels []sarifRelationship

		if cweID != nil {
			if cwe := cweID(f.RuleID); cwe != "" {
				rels = append(rels, sarifRelationship{
					Target: sarifRelationshipTarget{ID: cwe, ToolComponent: sarifToolComponentRef{Name: "CWE"}},
					Kinds:  []string{"superset"},
				})
				seenCWEs[cwe] = true
			}
		}

		if owasp != nil {
			for _, cat := range owasp(f.RuleID) {
				rels = append(rels, sarifRelationship{
					Target: sarifRelationshipTarget{ID: cat, ToolComponent: sarifToolComponentRef{Name: "OWASP Top 10 CI/CD Security Risks"}},
					Kinds:  []string{"superset"},
				})
				seenOWASP[cat] = true
			}
		}

		if asvs != nil {
			for _, req := range asvs(f.RuleID) {
				rels = append(rels, sarifRelationship{
					Target: sarifRelationshipTarget{ID: req, ToolComponent: sarifToolComponentRef{Name: "OWASP ASVS"}},
					Kinds:  []string{"superset"},
				})
				seenASVS[req] = true
			}
		}

		if len(rels) > 0 {
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
				ID: f.RuleID, Relationships: rels,
			})
		}
	}

	if len(seenCWEs) > 0 && cweName != nil {
		taxa := make([]sarifTaxon, 0, len(seenCWEs))
		for cwe := range seenCWEs {
			taxa = append(taxa, sarifTaxon{ID: cwe, Name: cweName(cwe)})
		}
		run.Taxonomies = append(run.Taxonomies, sarifTaxonomy{
			Name: "CWE", Version: "4.14", Organization: "MITRE", Taxa: taxa,
		})
	}

	if len(seenOWASP) > 0 && owaspName != nil {
		taxa := make([]sarifTaxon, 0, len(seenOWASP))
		for cat := range seenOWASP {
			taxa = append(taxa, sarifTaxon{ID: cat, Name: owaspName(cat)})
		}
		run.Taxonomies = append(run.Taxonomies, sarifTaxonomy{
			Name: "OWASP Top 10 CI/CD Security Risks", Version: "2022", Organization: "OWASP", Taxa: taxa,
		})
	}

	if len(seenASVS) > 0 && asvsName != nil {
		taxa := make([]sarifTaxon, 0, len(seenASVS))
		for req := range seenASVS {
			taxa = append(taxa, sarifTaxon{ID: req, Name: asvsName(req)})
		}
		run.Taxonomies = append(run.Taxonomies, sarifTaxonomy{
			Name: "OWASP ASVS", Version: "4.0.3", Organization: "OWASP", Taxa: taxa,
		})
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

// Code Climate JSON — consumed natively by GitLab's Code Quality widget
// (artifacts:reports:codequality). Spec:
// https://github.com/codeclimate/platform/blob/master/spec/analyzers/SPEC.md
type codeClimateIssue struct {
	Type        string              `json:"type"`
	CheckName   string              `json:"check_name"`
	Description string              `json:"description"`
	Categories  []string            `json:"categories"`
	Severity    string              `json:"severity"`
	Fingerprint string              `json:"fingerprint"`
	Location    codeClimateLocation `json:"location"`
}

type codeClimateLocation struct {
	Path  string           `json:"path"`
	Lines codeClimateLines `json:"lines"`
}

type codeClimateLines struct {
	Begin int `json:"begin"`
}

func severityToCodeClimate(s finding.Severity) string {
	switch s {
	case finding.Error:
		return "critical"
	case finding.Warn:
		return "major"
	default:
		return "info"
	}
}

func codeClimateFingerprint(f finding.Finding) string {
	h := sha256.Sum256([]byte(f.RuleID + "|" + f.File + "|" + f.Job + "|" + f.Message + "|" + fmt.Sprintf("%d", f.Line)))
	return hex.EncodeToString(h[:])
}

// WriteCodeClimate writes findings in the Code Climate JSON format
// consumed by GitLab's Code Quality (artifacts:reports:codequality).
func WriteCodeClimate(w io.Writer, findings []finding.Finding) error {
	return writeCodeClimate(w, findings)
}

func writeCodeClimate(w io.Writer, findings []finding.Finding) error {
	out := make([]codeClimateIssue, 0, len(findings))
	for _, f := range findings {
		out = append(out, codeClimateIssue{
			Type:        "issue",
			CheckName:   f.RuleID,
			Description: f.Message,
			Categories:  []string{"Security"},
			Severity:    severityToCodeClimate(f.Severity),
			Fingerprint: codeClimateFingerprint(f),
			Location: codeClimateLocation{
				Path:  f.File,
				Lines: codeClimateLines{Begin: f.Line},
			},
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
