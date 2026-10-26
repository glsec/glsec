// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl085 struct{}

var GL085 = &gl085{}

func (r *gl085) ID() string { return "GL085" }

// agentCmdRe finds a coding-agent CLI in command position: at the start of a
// command, after npx/bunx/pnpm dlx/exec/timeout/sudo, behind a package scope or
// a path, and after leading VAR=value assignments.
var agentCmdRe = regexp.MustCompile(
	`(?:^|[;&|(]|\$\()\s*(?:\w+=\S*\s+)*` +
		`(?:(?:npx|bunx)\s+(?:-y\s+|--yes\s+)?|pnpm\s+dlx\s+|exec\s+|timeout\s+\S+\s+|sudo\s+)?` +
		`(?:@[\w.-]+/|[\w./-]*/)?` +
		`(claude(?:-code)?|codex|gemini(?:-cli)?|copilot)(?:\s|$)`)

// agentBypassFlags lists, per agent, the flags that let it run tools such as
// the shell without asking.
var agentBypassFlags = map[string]*regexp.Regexp{
	"claude":  regexp.MustCompile(`--dangerously-skip-permissions\b|--permission-mode[=\s]+["']?bypassPermissions\b`),
	"codex":   regexp.MustCompile(`--dangerously-bypass-approvals-and-sandbox\b|--yolo\b|(?:--sandbox|-s)[=\s]+["']?danger-full-access\b`),
	"gemini":  regexp.MustCompile(`--yolo\b|(?:^|\s)-y(?:\s|$)|--approval-mode[=\s]+["']?yolo\b`),
	"copilot": regexp.MustCompile(`--allow-all-tools\b|--allow-all(?:\s|=|$)|--yolo\b`),
}

// agentPromptFlagRe marks an invocation that passes a prompt. The tainted-
// prompt check requires it, so an unrelated tool with the same name (the AWS
// Copilot CLI, for one) is not mistaken for an agent.
var agentPromptFlagRe = regexp.MustCompile(`(?:^|\s)(?:-p|--print|--prompt|--prompt-interactive|-i|exec)(?:[\s=]|$)`)

// allowedToolsRe finds Claude Code's tool allowlist flag; its value is checked
// for unrestricted Bash.
var allowedToolsRe = regexp.MustCompile(`--allowed-?[Tt]ools[=\s]+`)

var bashToolRe = regexp.MustCompile(`\bBash(\([^)]*\))?`)

// agentPromptVarRe matches the GL002 user-controlled variables, which include
// the comment that triggered a GitLab Duo flow (AI_FLOW_INPUT, AI_FLOW_CONTEXT).
var agentPromptVarRe = regexp.MustCompile(`\$\{?(` + strings.Join(userControlledVars, "|") + `)\b`)

func (r *gl085) Check(doc *yaml.Node, file string) []finding.Finding {
	mapping := parser.Unwrap(doc)
	workflowMR := workflowAllowsMR(mapping)
	var findings []finding.Finding
	// The agent lines of an item, cached for items shared through an anchor
	// (#766); the message still depends on the job.
	agents := nodeMemo[[]agentLine]{}
	EachScriptLinePerJob(doc, file, func(item *yaml.Node, file, job string) {
		found := agents.get(item, func() []agentLine {
			var out []agentLine
			for _, l := range logicalLines(item.Value) {
				if f, ok := checkAgentLine(l.text); ok {
					f.line = l.line
					out = append(out, f)
				}
			}
			return out
		})
		for _, f := range found {
			severity := finding.Warn
			msg := ""
			switch {
			case f.bypass != "" && f.taint != "":
				severity = finding.Error
				msg = fmt.Sprintf("AI agent %s runs with approvals disabled (%s) on a prompt containing user-controlled $%s — whoever writes that text can make the agent run any command with the job's token and secrets", f.agent, f.bypass, f.taint)
			case f.bypass != "":
				if agentJobOnMR(mapping, job, workflowMR) {
					severity = finding.Error
					msg = fmt.Sprintf("AI agent %s runs with approvals disabled (%s) in a job that runs on merge request pipelines — prompt injection through merge request content gives command execution with the job's token and secrets", f.agent, f.bypass)
				} else {
					msg = fmt.Sprintf("AI agent %s runs with approvals disabled (%s) — every tool call, shell commands included, runs without confirmation; allow only the tools the job needs", f.agent, f.bypass)
				}
			default:
				msg = fmt.Sprintf("user-controlled $%s in the prompt of AI agent %s — quoting stops shell injection but not prompt injection; keep the agent's tools narrow and its token read-only", f.taint, f.agent)
			}
			findings = append(findings, finding.Finding{
				RuleID:   "GL085",
				Severity: severity,
				Job:      job,
				Message:  msg,
				File:     file,
				Line:     parser.ScalarContentLine(item, f.line),
				Col:      item.Column,
			})
		}
	})
	return findings
}

type agentLine struct {
	agent, bypass, taint string
	line                 int // index of the item line the call starts on
}

// checkAgentLine inspects one physical script line. Flags and variables only
// count inside the agent's own command, up to the next |, ; or &.
func checkAgentLine(line string) (agentLine, bool) {
	m := agentCmdRe.FindStringSubmatchIndex(line)
	if m == nil {
		return agentLine{}, false
	}
	agent := line[m[2]:m[3]]
	agent = strings.TrimSuffix(strings.TrimSuffix(agent, "-code"), "-cli")
	segment := line[m[3]:]
	if end := strings.IndexAny(segment, "|;&"); end >= 0 {
		segment = segment[:end]
	}
	res := agentLine{agent: agent}
	if b := agentBypassFlags[agent].FindString(segment); b != "" {
		res.bypass = strings.TrimSpace(b)
	} else if agent == "claude" {
		res.bypass = unrestrictedBash(segment)
	}
	if agentPromptFlagRe.MatchString(segment) {
		if v := agentPromptVarRe.FindStringSubmatch(segment); v != nil {
			res.taint = v[1]
		}
	}
	if res.bypass == "" && res.taint == "" {
		return agentLine{}, false
	}
	return res, true
}

// unrestrictedBash reports a Claude Code --allowedTools value that grants Bash
// without a command pattern, or with the match-all pattern Bash(*).
func unrestrictedBash(segment string) string {
	loc := allowedToolsRe.FindStringIndex(segment)
	if loc == nil {
		return ""
	}
	value := flagValue(segment[loc[1]:])
	for _, m := range bashToolRe.FindAllStringSubmatch(value, -1) {
		pattern := strings.TrimSpace(strings.Trim(m[1], "()"))
		if m[1] == "" || pattern == "*" || pattern == ":*" {
			return "--allowedTools " + m[0]
		}
	}
	return ""
}

// agentJobOnMR reports whether a job runs on merge request pipelines: its own
// rules or only: name them, or it has none and workflow:rules admit them.
func agentJobOnMR(mapping *yaml.Node, job string, workflowMR bool) bool {
	node := parser.FindKey(mapping, job)
	if node == nil || node.Kind != yaml.MappingNode {
		return false
	}
	if jobHasMRTrigger(node) {
		return true
	}
	return workflowMR && jobGuardState(node) == guardAbsent
}

// workflowAllowsMR reports whether workflow:rules let merge request pipelines run.
func workflowAllowsMR(mapping *yaml.Node) bool {
	workflow := parser.FindKey(mapping, "workflow")
	if workflow == nil {
		return false
	}
	rules := parser.FindKey(workflow, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return false
	}
	for _, item := range rules.Content {
		cond := parser.FindKey(item, "if")
		if cond == nil || !strings.Contains(cond.Value, "merge_request") {
			continue
		}
		if when := parser.FindKey(item, "when"); when != nil && when.Value == "never" {
			continue
		}
		return true
	}
	return false
}

// flagValue returns a flag's argument: up to the closing quote when quoted,
// otherwise up to the next whitespace. Tool patterns such as
// Bash(git --no-pager diff:*) contain spaces and dashes of their own.
func flagValue(s string) string {
	if s != "" && (s[0] == '"' || s[0] == '\'') {
		if end := strings.IndexByte(s[1:], s[0]); end >= 0 {
			return s[1 : end+1]
		}
		return s[1:]
	}
	if end := strings.IndexAny(s, " \t"); end >= 0 {
		return s[:end]
	}
	return s
}
