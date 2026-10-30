// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package shellcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

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
	// approximate is set when yamlLine is where the scalar's content starts,
	// not the line itself; ShellCheck's column then belongs to another line.
	approximate bool
}

type scriptBlock struct {
	jobName string
	lines   []scriptLine
}

// Timeout is how long one ShellCheck call may take (#907). A script block is a
// few hundred lines at most, which ShellCheck checks in well under a second.
var Timeout = 30 * time.Second

// Run extracts all script blocks from doc and passes them to shellcheck.
// binPath is the path to the shellcheck binary; if empty, PATH is searched.
// A missing binary only logs a warning to stderr, as documented. A ShellCheck
// that fails, prints something that isn't its JSON, or runs past Timeout is an
// error (#907): ShellCheck was turned on, so a run without its findings must
// not pass as clean.
func Run(doc *yaml.Node, file string, binPath string) ([]finding.Finding, error) {
	bin, err := resolveBinary(binPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: shellcheck: %v — skipping\n", err)
		return nil, nil
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
		// run: is the CI/CD Steps alternative to script: and excludes it, so a
		// job using steps has no script: block for ShellCheck to see. Each step
		// is a separate shell invocation and is checked on its own.
		for _, node := range parser.RunStepBlocks(job) {
			if lines := extractLines(node); len(lines) > 0 {
				blocks = append(blocks, scriptBlock{jobName: name.Value, lines: lines})
			}
		}
	})

	var findings []finding.Finding
	for _, block := range blocks {
		comments, err := invoke(bin, block.lines)
		if err != nil {
			return nil, fmt.Errorf("shellcheck: job %q: %w", block.jobName, err)
		}
		for _, c := range comments {
			idx := c.Line - 1
			if idx < 0 || idx >= len(block.lines) {
				continue
			}
			col := c.Column
			if block.lines[idx].approximate {
				col = 0
			}
			findings = append(findings, finding.Finding{
				RuleID:   fmt.Sprintf("SC%d", c.Code),
				Severity: mapSeverity(c.Level),
				Job:      block.jobName,
				Message:  c.Message,
				File:     file,
				Line:     block.lines[idx].yamlLine,
				Col:      col,
			})
		}
	}
	return findings, nil
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

	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--format=json1", "--shell=bash", "--norc", tmp.Name()) //nolint:gosec
	// A child process the binary started may keep the output pipes open after
	// the kill; stop waiting for it after a second.
	cmd.WaitDelay = time.Second
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, execErr := cmd.Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("did not finish within %s", Timeout)
	}
	if execErr != nil {
		var exit *exec.ExitError
		if !errors.As(execErr, &exit) || exit.ExitCode() > 1 {
			return nil, withStderr(execErr, stderr.String())
		}
		// exit code 1 = findings found — expected
	}
	if len(out) == 0 {
		return nil, nil
	}
	var result scOutput
	if err := json.Unmarshal(out, &result); err != nil {
		return nil, withStderr(fmt.Errorf("parse output: %w", err), stderr.String())
	}
	return result.Comments, nil
}

// withStderr adds the start of ShellCheck's stderr to err: it usually says why
// the run failed. The caller sanitizes the message before printing it.
func withStderr(err error, stderr string) error {
	msg := strings.Join(strings.Fields(stderr), " ")
	if msg == "" {
		return err
	}
	if len(msg) > 300 {
		msg = msg[:300] + "…"
	}
	return fmt.Errorf("%w: %s", err, msg)
}

func resolveBinary(path string) (string, error) {
	if path != "" {
		if _, err := os.Stat(path); err != nil { //nolint:gosec // G703: the path comes from --shellcheck-path or an explicit --config, never from a config glsec found by itself
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
	// An unresolved !reference holds its path, not commands (#746).
	if seqNode == nil || seqNode.Kind != yaml.SequenceNode || parser.IsReference(seqNode) {
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
		parts := strings.Split(val, "\n")
		for i, part := range parts {
			if part == "" && i == len(parts)-1 {
				continue // trailing newline from block scalar
			}
			lines = append(lines, scriptLine{
				content:     part,
				yamlLine:    parser.ScalarContentLine(item, i),
				approximate: !parser.ScalarLineExact(item, i),
			})
		}
	}
	return lines
}
