// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl042 struct{}

var GL042 = &gl042{}

func (r *gl042) ID() string { return "GL042" }

type tlsCheck struct {
	tool string
	re   prefiltered
	msg  string
}

var tlsChecks = []tlsCheck{
	{
		tool: "curl",
		re:   mustCompilePrefiltered(`\bcurl\b.*\s(?:-k|--insecure)\b`),
		msg:  `curl invoked with "%s" — TLS certificate verification disabled; use --cacert to trust a specific CA instead`,
	},
	{
		tool: "wget",
		re:   mustCompilePrefiltered(`\bwget\b.*--no-check-certificate\b`),
		msg:  `wget invoked with "--no-check-certificate" — TLS certificate verification disabled; add the CA certificate to the system trust store instead`,
	},
	{
		tool: "git",
		re:   mustCompilePrefiltered(`\bgit\b.*-c\s+http\.sslVerify\s*=\s*false\b`),
		msg:  `git invoked with "http.sslVerify=false" — TLS certificate verification disabled; configure the CA with http.sslCAInfo instead`,
	},
	{
		tool: "npm",
		re:   mustCompilePrefiltered(`\bnpm\b.*--strict-ssl\s*=?\s*false\b`),
		msg:  `npm invoked with "--strict-ssl=false" — TLS certificate verification disabled; use cafile in .npmrc to trust a specific CA instead`,
	},
	{
		tool: "npm config",
		re:   mustCompilePrefiltered(`\bnpm\s+(?:config\s+set|set)\s+strict-ssl\s+false\b`),
		msg:  `npm strict-ssl disabled via "npm config set" — TLS certificate verification disabled for all subsequent npm commands`,
	},
	{
		tool: "pip",
		re:   mustCompilePrefiltered(`\bpip[0-9]*\b.*--trusted-host\b`),
		msg:  `pip invoked with "--trusted-host" — TLS certificate verification disabled for the package index, allowing a man-in-the-middle to swap package contents; add the proxy CA to the system trust store instead`,
	},
	{
		tool: "kubectl/helm",
		re:   mustCompilePrefiltered(`\b(?:kubectl|helm)\b.*--insecure-skip-tls-verify(?:=true)?(?:\s|$)`),
		msg:  `kubectl or helm invoked with "--insecure-skip-tls-verify" — the API server's certificate isn't checked, so a man-in-the-middle sees the cluster credentials; set certificate-authority in the kubeconfig instead`,
	},
	{
		tool: "podman/buildah/skopeo",
		re:   mustCompilePrefiltered(`\b(?:podman|buildah|skopeo)\b.*--(?:src-|dest-)?tls-verify=false\b`),
		msg:  `container tool invoked with "--tls-verify=false" — TLS certificate verification disabled for the registry, allowing a man-in-the-middle to swap images; add the registry CA to the trust store instead`,
	},
	{
		// Kaniko, GitLab's documented rootless image builder (#1386). The
		// -registry forms take a registry name; the others are booleans, so
		// --insecure=false is not reported.
		tool: "kaniko",
		re:   mustCompilePrefiltered(`\bkaniko\b.*\s--(?:(?:insecure|skip-tls-verify)(?:-pull)?(?:=true)?(?:\s|$)|(?:insecure|skip-tls-verify)-registry(?:=|\s))`),
		msg:  `kaniko invoked with "%s" — the registry's certificate isn't checked (or plain HTTP is used), so a man-in-the-middle can swap the base image or receive the pushed one; trust the registry CA with --registry-certificate instead`,
	},
	{
		tool: "dockerd",
		re:   mustCompilePrefiltered(`\bdockerd\b.*--insecure-registry\b`),
		msg:  insecureRegistryMsg,
	},
}

// kanikoFlagRe finds the flag a kaniko match reports. The match's greedy .*
// makes it end at the last such flag on the line.
var kanikoFlagRe = mustCompilePrefiltered(`--(?:insecure|skip-tls-verify)(?:-pull|-registry)?`)

const insecureRegistryMsg = `dockerd started with "--insecure-registry" — TLS certificate verification disabled for the registry, allowing a man-in-the-middle to swap images; add the registry CA to the certs.d directory instead`

// tlsVarChecks are environment variables that disable TLS verification, in a
// script or in variables:.
var tlsVarChecks = []struct {
	name     string
	re       prefiltered
	insecure func(value string) bool
	effect   string
}{
	{
		name:     "NODE_TLS_REJECT_UNAUTHORIZED",
		re:       mustCompilePrefiltered(`\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0\b`),
		insecure: func(value string) bool { return value == "0" },
		effect:   "TLS certificate verification disabled for every Node.js process",
	},
	{
		name:     "PIP_TRUSTED_HOST",
		re:       mustCompilePrefiltered(`\bPIP_TRUSTED_HOST\s*=\s*["']?[^\s"']`),
		insecure: func(value string) bool { return value != "" },
		effect:   "TLS certificate verification disabled for the package index",
	},
}

// gitSSLNoVerifyRe matches GIT_SSL_NO_VERIFY=true/1 as a variable export or inline env.
var gitSSLNoVerifyRe = mustCompilePrefiltered(`\bGIT_SSL_NO_VERIFY\s*=\s*(?:true|1)\b`)

func (r *gl042) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	mapping := parser.Unwrap(doc)

	eachVariablesBlock(doc, func(vars *yaml.Node, job string, _ *yaml.Node) {
		if vars != nil {
			findings = append(findings, checkGitSSLNoVerifyVars(vars, file, job)...)
			findings = append(findings, checkTLSVars(vars, file, job)...)
		}
	})

	for _, key := range []string{"before_script", "after_script"} {
		if node := parser.FindKey(mapping, key); node != nil {
			findings = append(findings, checkTLSLines(node, file, "")...)
		}
	}
	findings = append(findings, checkInsecureRegistry(parser.FindKey(mapping, "services"), file, "")...)
	if def := parser.FindKey(mapping, "default"); def != nil {
		findings = append(findings, checkInsecureRegistry(parser.FindKey(def, "services"), file, "")...)
		for _, key := range []string{"before_script", "after_script"} {
			if node := parser.FindKey(def, key); node != nil {
				findings = append(findings, checkTLSLines(node, file, "")...)
			}
		}
		if h := hookScriptNode(def); h != nil {
			findings = append(findings, checkTLSLines(h, file, "")...)
		}
	}

	// A block shared by several jobs through an anchor is checked once; the
	// other jobs' findings would be merged by finding.Dedupe (#766).
	seen := map[*yaml.Node]bool{}
	once := func(n *yaml.Node) bool {
		if n == nil || seen[n] {
			return false
		}
		seen[n] = true
		return true
	}
	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		jobScripts := []*yaml.Node{
			parser.FindKey(job, "script"),
			parser.FindKey(job, "before_script"),
			parser.FindKey(job, "after_script"),
		}
		jobScripts = append(jobScripts, parser.RunStepBlocks(job)...)
		for _, node := range jobScripts {
			if once(node) {
				findings = append(findings, checkTLSLines(node, file, name.Value)...)
			}
		}
		if h := hookScriptNode(job); once(h) {
			findings = append(findings, checkTLSLines(h, file, name.Value)...)
		}
		if s := parser.FindKey(job, "services"); once(s) {
			findings = append(findings, checkInsecureRegistry(s, file, name.Value)...)
		}
	})

	return findings
}

func checkTLSLines(node *yaml.Node, file, job string) []finding.Finding {
	if !isScriptList(node) {
		return nil
	}
	var findings []finding.Finding
	for _, item := range node.Content {
		if item.Kind != yaml.ScalarNode {
			continue
		}
		for _, check := range tlsChecks {
			loc := check.re.FindStringIndex(item.Value)
			if loc == nil {
				continue
			}
			m := item.Value[loc[0]:loc[1]]
			line, col := scriptMatchPos(item, loc[0])
			msg := check.msg
			if check.tool == "curl" {
				flag := mustCompilePrefiltered(`-k|--insecure`).FindString(m)
				msg = fmt.Sprintf(msg, flag)
			}
			if check.tool == "kaniko" {
				flags := kanikoFlagRe.FindAllStringIndex(m, -1)
				last := flags[len(flags)-1]
				msg = fmt.Sprintf(msg, m[last[0]:last[1]])
			}
			findings = append(findings, finding.Finding{
				RuleID:   "GL042",
				Severity: finding.Warn,
				Job:      job,
				Message:  msg,
				File:     file,
				Line:     line,
				Col:      col,
			})
			break
		}

		if loc := gitSSLNoVerifyRe.FindStringIndex(item.Value); loc != nil {
			line, col := scriptMatchPos(item, loc[0])
			// The value as written: =1 or =true (#1005).
			setting := strings.Join(strings.Fields(item.Value[loc[0]:loc[1]]), "")
			findings = append(findings, finding.Finding{
				RuleID:   "GL042",
				Severity: finding.Warn,
				Job:      job,
				Message:  setting + ` in script — TLS certificate verification disabled for all git operations in this step`,
				File:     file,
				Line:     line,
				Col:      col,
			})
		}
		for _, check := range tlsVarChecks {
			loc := check.re.FindStringIndex(item.Value)
			if loc == nil {
				continue
			}
			line, col := scriptMatchPos(item, loc[0])
			findings = append(findings, finding.Finding{
				RuleID:   "GL042",
				Severity: finding.Warn,
				Job:      job,
				Message:  check.name + " set in script — " + check.effect,
				File:     file,
				Line:     line,
				Col:      col,
			})
		}
	}
	return findings
}

// checkInsecureRegistry flags a service, such as docker:dind, whose command or
// entrypoint passes --insecure-registry to dockerd.
func checkInsecureRegistry(services *yaml.Node, file, job string) []finding.Finding {
	if services == nil || services.Kind != yaml.SequenceNode {
		return nil
	}
	var findings []finding.Finding
	for _, service := range services.Content {
		for _, key := range []string{"command", "entrypoint"} {
			args := parser.FindKey(service, key)
			if args == nil || args.Kind != yaml.SequenceNode {
				continue
			}
			for i, arg := range args.Content {
				if !strings.HasPrefix(arg.Value, "--insecure-registry") {
					continue
				}
				// The runner passes services:command and entrypoint to the
				// container unexpanded, so a $VAR value reaches dockerd as
				// literal text and names no registry (#1273).
				value, ok := strings.CutPrefix(arg.Value, "--insecure-registry=")
				if !ok && i+1 < len(args.Content) {
					value = args.Content[i+1].Value
				}
				if !strings.Contains(value, "$") {
					findings = append(findings, finding.Finding{
						RuleID:   "GL042",
						Severity: finding.Warn,
						Job:      job,
						Message:  insecureRegistryMsg,
						File:     file,
						Line:     arg.Line,
						Col:      arg.Column,
					})
				}
			}
		}
	}
	return findings
}

// checkTLSVars flags the tlsVarChecks variables set in a variables: block.
func checkTLSVars(node *yaml.Node, file, job string) []finding.Finding {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	var findings []finding.Finding
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		val := resolveScalar(node.Content[i+1])
		for _, check := range tlsVarChecks {
			if key.Value == check.name && val != nil && check.insecure(val.Value) {
				findings = append(findings, finding.Finding{
					RuleID:   "GL042",
					Severity: finding.Warn,
					Job:      job,
					Message:  fmt.Sprintf("%s set to %q in variables — %s", check.name, val.Value, check.effect),
					File:     file,
					Line:     key.Line,
					Col:      key.Column,
				})
			}
		}
	}
	return findings
}

func checkGitSSLNoVerifyVars(node *yaml.Node, file, job string) []finding.Finding {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	var findings []finding.Finding
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		val := node.Content[i+1]
		if key.Value == "GIT_SSL_NO_VERIFY" && (val.Value == "true" || val.Value == "1") {
			findings = append(findings, finding.Finding{
				RuleID:   "GL042",
				Severity: finding.Warn,
				Job:      job,
				Message:  fmt.Sprintf("GIT_SSL_NO_VERIFY set to %q in variables — TLS certificate verification disabled for all git operations in affected jobs", val.Value),
				File:     file,
				Line:     key.Line,
				Col:      key.Column,
			})
		}
	}
	return findings
}
