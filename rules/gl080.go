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

type gl080 struct{}

var GL080 = &gl080{}

func (r *gl080) ID() string { return "GL080" }

func (r *gl080) Check(doc *yaml.Node, file string) []finding.Finding {
	mapping := parser.Unwrap(doc)

	// A restricting top-level workflow:rules gates every job's pipeline source,
	// so no job needs its own guard. Suppress conservatively: any workflow:rules
	// carrying an if: condition is treated as restricting the source. It does
	// not change which jobs run only in merge request pipelines (#1142).
	wfRestricts := workflowRestrictsSource(mapping)
	mrPipelines := !wfRestricts || workflowAdmitsMR(mapping)
	if wfRestricts && !mrPipelines {
		return nil
	}

	in := NewInheritance(doc)
	var findings []finding.Finding
	parser.EachJob(doc, func(name *yaml.Node, own *yaml.Node) {
		// Hidden jobs (names starting with ".") are templates GitLab never runs.
		if strings.HasPrefix(name.Value, ".") {
			return
		}
		// A base in another file may hold the guard: skip the job rather than
		// report a guard that is present but invisible here. A chain within
		// this file is merged in.
		if !in.ExtendsResolved(own) || in.IncludedOverride(own) {
			return
		}
		job := in.Effective(own)
		// The production-environment-without-rules case is already covered by
		// GL013; skip it here to avoid a duplicate finding.
		if gl013Owns(name.Value, job) {
			return
		}
		state := jobGuardState(job)
		msg := ""
		switch {
		case state != guardEffective && !wfRestricts:
			// An unguarded job is reported only when it really deploys: an
			// environment, a deploy/publish/infra-apply command, or a
			// deploy-named job that uses a credential (#1371). A deploy-sounding
			// name alone is not enough.
			if !gl080Sensitive(in, name.Value, own, job) {
				return
			}
			msg = gl080Message(name.Value, state, jobManualOnly(job))
		case state == guardEffective && mrPipelines && gl080MROnlyProduction(in, name.Value, own, job):
			msg = fmt.Sprintf(
				"sensitive job %q runs only in merge request pipelines — it deploys or publishes the MR's source commit before anyone merged it, and to work there its credentials can't be protected variables, so every branch can read them; restrict the job to the protected branch ($CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH) or to tags",
				name.Value,
			)
		default:
			return
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL080",
			Severity: finding.Warn,
			Job:      name.Value,
			Message:  msg,
			File:     file,
			Line:     name.Line,
			Col:      name.Column,
		})
	})
	return findings
}

// testRegistryRe matches a publish to a test index or to the project's own
// GitLab package registry, which an MR build may be meant for.
var testRegistryRe = mustCompilePrefiltered(`(?i)test\.pypi\.org|testpypi|CI_API_V4_URL|CI_SERVER_URL|CI_JOB_TOKEN|--dry-run`)

// gl080MROnlyProduction reports a job without environment: that runs only in
// merge request pipelines and deploys to production by its name or publishes
// a package to a public registry (#1142). A job with an environment: is
// GL013's: production there, a review app otherwise.
func gl080MROnlyProduction(in *Inheritance, name string, own, job *yaml.Node) bool {
	if parser.FindKey(job, "environment") != nil || !runsOnlyInMRPipelines(in, own) {
		return false
	}
	if productionName(name, false) || productionName(jobStageName(job), false) {
		return true
	}
	vars := parser.FindKey(job, "variables")
	for _, key := range []string{"before_script", "script"} {
		block := parser.FindKey(job, key)
		if !isScriptList(block) {
			continue
		}
		for _, item := range block.Content {
			if item.Kind != yaml.ScalarNode || !mentionsPublish(item.Value) {
				continue
			}
			for _, cmd := range shellCommands(item.Value) {
				if testRegistryRe.MatchString(cmd.text) {
					continue
				}
				words := commandWords(cmd.text)
				for _, eco := range lifecycleEcosystems {
					if eco.publishes(words) && !publishesToTestRegistry(vars) {
						return true
					}
				}
			}
		}
	}
	return false
}

// publishesToTestRegistry reports a variables: block that points the publish
// tools at a test index or the GitLab package registry.
func publishesToTestRegistry(vars *yaml.Node) bool {
	if vars == nil || vars.Kind != yaml.MappingNode {
		return false
	}
	for i := 1; i < len(vars.Content); i += 2 {
		v := vars.Content[i]
		if v.Kind == yaml.MappingNode {
			v = parser.FindKey(v, "value")
		}
		if v != nil && v.Kind == yaml.ScalarNode && testRegistryRe.MatchString(v.Value) {
			return true
		}
	}
	return false
}

// workflowAdmitsMR reports whether workflow:rules, which
// workflowRestrictsSource found, can let a merge request pipeline run: a rule
// without if:, or one that tests a merge request or neither the branch, the
// tag nor the pipeline source.
func workflowAdmitsMR(mapping *yaml.Node) bool {
	rules := parser.FindKey(parser.FindKey(mapping, "workflow"), "rules")
	for _, item := range rules.Content {
		if item.Kind != yaml.MappingNode {
			return true
		}
		if ruleExcludes(item) {
			continue
		}
		ifNode := parser.FindKey(item, "if")
		if ifNode == nil || ifNode.Kind != yaml.ScalarNode {
			return true
		}
		e := ifNode.Value
		if strings.Contains(e, "merge_request") || strings.Contains(e, "CI_MERGE_REQUEST_") ||
			!branchOrTagRe.MatchString(e) && !strings.Contains(e, "CI_PIPELINE_SOURCE") {
			return true
		}
	}
	return false
}

// gl080DeployKeywords are the narrow set of job/stage name fragments that
// reliably indicate a deployment or external publish. Broader terms used
// elsewhere (push, upload, dist, ship, migrate) matched too many build/cache
// jobs in real pipelines, so they are intentionally excluded here.
var gl080DeployKeywords = []string{"deploy", "rollout", "release", "publish", "provision"}

// gl080NotDeployKeywords mark jobs that only build, test, or package artifacts —
// e.g. a "release build" or "docdist" is not a deployment. They veto a keyword
// match so "windows-release-build" or "coverage-review" is not flagged.
var gl080NotDeployKeywords = []string{
	"build", "compile", "test", "lint", "cache", "coverage",
	"check", "package", "bundle", "prepare", "validate", "audit",
	"scan", "review", "dist",
}

// gl080Sensitive reports whether a job deploys or publishes to an external
// target. A deploy-sounding job name is not enough on its own — at scale it
// flagged jobs that only build a local artifact, run tests, or generate files,
// with no credential to steal on a fork MR (#1371). A job is sensitive when:
//
//   - it has an environment: (other than a teardown/stop job); or
//   - its effective script runs a real deploy, publish or infrastructure-apply
//     command (docker/podman push, npm/twine/cargo publish, kubectl/helm/
//     terraform/pulumi apply, rsync/scp, …) — this also catches an infra-apply
//     job whose name is `terraform` or `plan-apply`, not `deploy`; or
//   - it has a deploy/release/publish-named job or stage AND uses a credential
//     (a secret-named variable), so a custom deploy (`./deploy.sh "$TOKEN"`)
//     glsec can't read as a command still counts, while a `publish-docs` or
//     `release-notes` job with no credential does not.
func gl080Sensitive(in *Inheritance, name string, own, job *yaml.Node) bool {
	if env := parser.FindKey(job, "environment"); env != nil && !envActionStop(env) && extractEnvName(env) != "" {
		return true
	}
	// A GitLab Pages job publishes a site — a deployment. The main-site case is
	// GL013's and has already returned via gl013Owns, so a Pages job reaching
	// gl080Sensitive is a path-prefixed (non-main) deploy.
	if name == "pages" || parser.FindKey(job, "pages") != nil {
		return true
	}
	if jobScriptDeploys(in, own) {
		return true
	}
	hay := strings.ToLower(name) + " " + jobStageName(job)
	for _, neg := range gl080NotDeployKeywords {
		if strings.Contains(hay, neg) {
			return false
		}
	}
	for _, kw := range gl080DeployKeywords {
		if strings.Contains(hay, kw) {
			return jobUsesCredential(job)
		}
	}
	return false
}

// jobUsesCredential reports whether a job's effective definition carries a
// secret: a secret-named variable set in variables:, or referenced in a
// script line (`$DEPLOY_TOKEN`, `$CI_REGISTRY_PASSWORD`). It gates the
// name-keyword path of gl080Sensitive so a deploy-named job counts only when
// it actually has a credential to protect.
func jobUsesCredential(job *yaml.Node) bool {
	if vars := parser.FindKey(job, "variables"); vars != nil && vars.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(vars.Content); i += 2 {
			if isSecretName(strings.ToUpper(vars.Content[i].Value)) {
				return true
			}
		}
	}
	for _, line := range CollectJobScriptLines(job) {
		for _, loc := range gl021VarRefRe.FindAllStringSubmatchIndex(line.Value, -1) {
			if isSecretName(line.Value[loc[2]:loc[3]]) {
				return true
			}
		}
	}
	return false
}

func jobStageName(job *yaml.Node) string {
	if s := parser.FindKey(job, "stage"); s != nil && s.Kind == yaml.ScalarNode {
		return strings.ToLower(s.Value)
	}
	return ""
}

// envActionStop reports whether an environment: block is a teardown job
// (environment:action: stop), which tears an environment down rather than
// deploying to it and carries little source-guard risk.
func envActionStop(env *yaml.Node) bool {
	if env.Kind != yaml.MappingNode {
		return false
	}
	if a := parser.FindKey(env, "action"); a != nil && a.Kind == yaml.ScalarNode {
		return a.Value == "stop"
	}
	return false
}

type guardState int

const (
	guardAbsent      guardState = iota // no rules:/only:/except: at all
	guardIneffective                   // rules: present but no if:/changes:/exists: condition
	guardEffective                     // has a real restriction
)

func gl080Message(job string, state guardState, manual bool) string {
	// when: manual is the job's only gate. It is not a pipeline-source
	// restriction: the job is still created on every source, and a maintainer
	// can start it on a fork merge request, where it runs the fork's code with
	// this job's credentials. So GL080 still flags it, but the message says so
	// accurately rather than claiming an external contributor can trigger it
	// (#1124).
	if manual {
		return fmt.Sprintf(
			"sensitive job %q is gated only by when: manual, which is not a pipeline-source restriction — a maintainer can still start it on a fork merge request, where it runs untrusted code with this job's credentials; add a rules:if that checks $CI_PIPELINE_SOURCE",
			job,
		)
	}
	if state == guardIneffective {
		return fmt.Sprintf(
			"sensitive job %q has a rules: block with no if:/changes:/exists: condition — the gate imposes no restriction, so the job runs on every pipeline source including fork merge requests; add a rules:if that checks $CI_PIPELINE_SOURCE",
			job,
		)
	}
	return fmt.Sprintf(
		"sensitive job %q has no rules:/only:/except: guard — it runs on every pipeline source including fork merge requests; add a rules:if that checks $CI_PIPELINE_SOURCE",
		job,
	)
}

// jobManualOnly reports whether the job's trigger gate is when: manual — a
// top-level when: manual, or a rules: item that sets when: manual. A manual
// gate is not a pipeline-source restriction, so GL080 keeps flagging the job
// but words the finding for the manual case (#1124).
func jobManualOnly(job *yaml.Node) bool {
	if w := parser.FindKey(job, "when"); w != nil && w.Kind == yaml.ScalarNode {
		return w.Value == "manual"
	}
	rules := parser.FindKey(job, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return false
	}
	for _, item := range rules.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		if w := parser.FindKey(item, "when"); w != nil && w.Kind == yaml.ScalarNode && w.Value == "manual" {
			return true
		}
	}
	return false
}

// jobGuardState classifies a job's execution guard. only:/except: (legacy) and
// any rules item carrying an if:/changes:/exists: condition count as effective.
func jobGuardState(job *yaml.Node) guardState {
	if parser.FindKey(job, "only") != nil || parser.FindKey(job, "except") != nil {
		return guardEffective
	}
	rules := parser.FindKey(job, "rules")
	if rules == nil {
		return guardAbsent
	}
	// A !reference that points into an included file can't be read here: the
	// rules it stands for are unknown, so they count as a guard (#979).
	if rules.Kind != yaml.SequenceNode || parser.IsReference(rules) {
		return guardEffective
	}
	for _, item := range rules.Content {
		if parser.IsReference(item) {
			return guardEffective
		}
		if item.Kind != yaml.MappingNode {
			continue
		}
		if parser.FindKey(item, "if") != nil ||
			parser.FindKey(item, "changes") != nil ||
			parser.FindKey(item, "exists") != nil {
			return guardEffective
		}
	}
	return guardIneffective
}

// gl013Owns reports whether GL013 already flags this job (a production-like
// environment or the main Pages site, with no rules:/only: restriction), so
// GL080 can defer to it.
func gl013Owns(name string, job *yaml.Node) bool {
	if !hasExecutionRestriction(job) && publishesMainPages(name, parser.FindKey(job, "pages")) {
		return true
	}
	env := parser.FindKey(job, "environment")
	if env == nil {
		return false
	}
	envName := extractEnvName(env)
	tier := extractDeploymentTier(env)
	prod := (envName != "" && isProdEnv(envName)) || isProdTier(tier)
	return prod && !hasExecutionRestriction(job)
}

// workflowRestrictsSource reports whether top-level workflow:rules carries any
// if: condition — treated as restricting which pipeline sources run at all.
func workflowRestrictsSource(mapping *yaml.Node) bool {
	wf := parser.FindKey(mapping, "workflow")
	if wf == nil {
		return false
	}
	rules := parser.FindKey(wf, "rules")
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return false
	}
	for _, item := range rules.Content {
		if item.Kind == yaml.MappingNode && parser.FindKey(item, "if") != nil {
			return true
		}
	}
	return false
}
