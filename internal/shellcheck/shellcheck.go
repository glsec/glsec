package shellcheck

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type scComment struct {
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Level   string `json:"level"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type scOutput struct {
	Comments []scComment `json:"comments"`
}

type scriptLine struct {
	content  string
	yamlLine int
}

type scriptBlock struct {
	jobName string
	lines   []scriptLine
}

// Run extracts all script blocks from doc and passes them to shellcheck.
// binPath is the path to the shellcheck binary; if empty, PATH is searched.
// Returns an empty slice and logs a warning to stderr if the binary is not found.
func Run(doc *yaml.Node, file string, binPath string) []finding.Finding {
	bin, err := resolveBinary(binPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: shellcheck: %v — skipping\n", err)
		return nil
	}

	mapping := parser.Unwrap(doc)
	var blocks []scriptBlock

	for _, key := range []string{"before_script", "after_script"} {
		if node := parser.FindKey(mapping, key); node != nil {
			if lines := extractLines(node); len(lines) > 0 {
				blocks = append(blocks, scriptBlock{jobName: key, lines: lines})
			}
		}
	}
	if def := parser.FindKey(mapping, "default"); def != nil {
		for _, key := range []string{"before_script", "after_script"} {
			if node := parser.FindKey(def, key); node != nil {
				if lines := extractLines(node); len(lines) > 0 {
					blocks = append(blocks, scriptBlock{jobName: "default." + key, lines: lines})
				}
			}
		}
		if node := hooksScriptNode(def); node != nil {
			if lines := extractLines(node); len(lines) > 0 {
				blocks = append(blocks, scriptBlock{jobName: "default.hooks:pre_get_sources_script", lines: lines})
			}
		}
	}
	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		for _, key := range []string{"script", "before_script", "after_script"} {
			if node := parser.FindKey(job, key); node != nil {
				if lines := extractLines(node); len(lines) > 0 {
					blocks = append(blocks, scriptBlock{jobName: name.Value, lines: lines})
				}
			}
		}
		if node := hooksScriptNode(job); node != nil {
			if lines := extractLines(node); len(lines) > 0 {
				blocks = append(blocks, scriptBlock{jobName: name.Value, lines: lines})
			}
		}
	})

	var findings []finding.Finding
	for _, block := range blocks {
		comments, err := invoke(bin, block.lines)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: shellcheck: job %q: %v\n", block.jobName, err)
			continue
		}
		for _, c := range comments {
			idx := c.Line - 1
			if idx < 0 || idx >= len(block.lines) {
				continue
			}
			findings = append(findings, finding.Finding{
				RuleID:   fmt.Sprintf("SC%d", c.Code),
				Severity: mapSeverity(c.Level),
				Job:      block.jobName,
				Message:  c.Message,
				File:     file,
				Line:     block.lines[idx].yamlLine,
				Col:      c.Column,
			})
		}
	}
	return findings
}

func invoke(bin string, lines []scriptLine) ([]scComment, error) {
	tmp, err := os.CreateTemp("", "glsec-sc-*.sh")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	var sb strings.Builder
	for _, l := range lines {
		sb.WriteString(l.content)
		sb.WriteByte('\n')
	}
	if _, err := tmp.WriteString(sb.String()); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	_ = tmp.Close()

	out, execErr := exec.Command(bin, "--format=json1", "--shell=bash", "--norc", tmp.Name()).Output() //nolint:gosec
	if execErr != nil {
		exit, ok := execErr.(*exec.ExitError)
		if !ok || exit.ExitCode() > 1 {
			return nil, execErr
		}
		// exit code 1 = findings found — expected
	}
	if len(out) == 0 {
		return nil, nil
	}
	var result scOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, fmt.Errorf("parse output: %w", err)
	}
	return result.Comments, nil
}

func resolveBinary(path string) (string, error) {
	if path != "" {
		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("binary not found at %q", path)
		}
		return path, nil
	}
	bin, err := exec.LookPath("shellcheck")
	if err != nil {
		return "", fmt.Errorf("binary not found in PATH")
	}
	return bin, nil
}

func mapSeverity(level string) finding.Severity {
	switch level {
	case "error":
		return finding.Error
	case "warning":
		return finding.Warn
	default:
		return finding.Info
	}
}

// hooksScriptNode returns the hooks:pre_get_sources_script sequence node for a
// job or default: mapping, or nil. These commands run on the runner before the
// repository is cloned and are valid shell to lint.
func hooksScriptNode(container *yaml.Node) *yaml.Node {
	hooks := parser.FindKey(container, "hooks")
	if hooks == nil {
		return nil
	}
	return parser.FindKey(hooks, "pre_get_sources_script")
}

// extractLines builds a flat slice of script lines with their YAML line numbers
// from a YAML sequence node (script:/before_script:/after_script:).
func extractLines(seqNode *yaml.Node) []scriptLine {
	if seqNode == nil || seqNode.Kind != yaml.SequenceNode {
		return nil
	}
	var lines []scriptLine
	for _, item := range seqNode.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		val := item.Value
		if !strings.Contains(val, "\n") {
			lines = append(lines, scriptLine{content: val, yamlLine: item.Line})
			continue
		}
		// Multi-line scalar: block scalars (| or >) start content one line after the indicator.
		startLine := item.Line
		if item.Style == yaml.LiteralStyle || item.Style == yaml.FoldedStyle {
			startLine++
		}
		parts := strings.Split(val, "\n")
		for i, part := range parts {
			if part == "" && i == len(parts)-1 {
				continue // trailing newline from block scalar
			}
			lines = append(lines, scriptLine{content: part, yamlLine: startLine + i})
		}
	}
	return lines
}
