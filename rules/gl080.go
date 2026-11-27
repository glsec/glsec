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

// CheckDocument reads the file in its pipeline context (#1502): a child
// pipeline or included file that only protected refs reach has no job that
// runs on an unprotected branch, and in a child pipeline started on any ref,
// if: $CI_PIPELINE_SOURCE == "parent_pipeline" restricts nothing.
func (r *gl080) CheckDocument(doc *parser.Document, file string) []finding.Finding {
	ctx := contextOf(doc)
	if ctx.protected || ctx.restricted {
		return nil
	}
	return r.check(doc.Root, file, ctx)
}

func (r *gl080) Check(doc *yaml.Node, file string) []finding.Finding {
	return r.check(doc, file, docContext{})
}

func (r *gl080) check(doc *yaml.Node, file string, ctx docContext) []finding.Finding {
	mapping := parser.Unwrap(doc)

	// A workflow:rules that admits protected refs only keeps every job off
	// unprotected branches. Any other workflow, such as GitLab's recommended
	// switch between branch and merge request pipelines, still runs an
	// unguarded job on every branch (#1492).
	scope := ctx.scope(mapping)
	if scope.protectedOnly {
		return nil
	}
	vars := parser.FindKey(mapping, "variables")

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
		severity := finding.Warn
		switch {
		case state != guardEffective:
			// An unguarded job is reported only when it really deploys: an
			// environment, a deploy/publish/infra-apply command, or a
			// deploy-named job that uses a credential (#1371). A deploy-sounding
			// name alone is not enough.
			sensitive, strong := gl080Sensitive(in, name.Value, own, job, vars)
			if !sensitive {
				return
			}
			if !strong {
				severity = finding.Info
			}
			msg = gl080Message(name.Value, state, jobManualOnly(job))
		case state == guardEffective && scope.mrPipelines && gl080MROnlyProduction(in, name.Value, own, job):
			msg = fmt.Sprintf(
				"sensitive job %q runs only in merge request pipelines — it deploys or publishes the MR's source commit before anyone merged it, and to work there its credentials can't be protected variables, so every branch can read them; restrict the job to the protected branch ($CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH) or to tags",
				name.Value,
			)
		case state == guardEffective:
			// A guard with an entry that matches on every branch, such as a
			// - when: manual fallback or changes: alone, restricts nothing:
			// GitLab runs the job by the first entry that matches (#1498).
			entry, _ := scope.fallbackEntry(parser.FindKey(job, "rules"))
			if entry == nil || gl013OwnsOpen(job) {
				return
			}
			sensitive, strong := gl080Sensitive(in, name.Value, own, withEntryVariables(job, entry), vars)
			if !sensitive {
				return
			}
			if !strong {
				severity = finding.Info
			}
			msg = fmt.Sprintf(
				"sensitive job %q has a rules: entry %s that matches on every branch — GitLab runs the job by the first entry that matches, so any branch can run it, also a fork's merge request a maintainer runs here; restrict that entry to protected refs or drop it",
				name.Value, gl080EntryLabel(entry),
			)
		default:
			return
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL080",
			Severity: severity,
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
	// A stage before the deploy prepares it (#1546).
	"pre-deploy", "predeploy", "pre_deploy", "pre-publish", "prepublish", "pre_publish",
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
func gl080Sensitive(in *Inheritance, name string, own, job, globalVars *yaml.Node) (sensitive, strong bool) {
	if env := parser.FindKey(job, "environment"); env != nil && !envActionStop(env) && extractEnvName(env) != "" && !ephemeralEnvironmentIn(env, parser.FindKey(job, "variables"), globalVars) {
		return true, true
	}
	// A GitLab Pages job publishes a site — a deployment. The main-site case is
	// GL013's and has already returned via gl013Owns, so a Pages job reaching
	// gl080Sensitive is a path-prefixed (non-main) deploy.
	if name == "pages" || parser.FindKey(job, "pages") != nil {
		return true, true
	}
	deploys, strong, discounted := gl080ScriptDeploys(in, job, globalVars)
	if deploys {
		return true, strong
	}
	hay := strings.ToLower(name) + " " + jobStageName(job)
	for _, neg := range gl080NotDeployKeywords {
		if strings.Contains(hay, neg) {
			return false, false
		}
	}
	for _, kw := range gl080DeployKeywords {
		if strings.Contains(hay, kw) {
			// A job whose every publish glsec reads ships nothing shared, and
			// the job's own CI_ token is no secret to steal: a fork's merge
			// request gets the fork's (#1524).
			return jobUsesCredential(job, discounted), false
		}
	}
	return false, false
}

// jobUsesCredential reports whether a job's effective definition carries a
// secret: a secret-named variable set in variables:, or referenced in a
// script line (`$DEPLOY_TOKEN`, `$CI_REGISTRY_PASSWORD`). It gates the
// name-keyword path of gl080Sensitive so a deploy-named job counts only when
// it actually has a credential to protect.
func jobUsesCredential(job *yaml.Node, skipJobTokens bool) bool {
	secret := func(name string) bool {
		return isSecretName(name) && (!skipJobTokens || !strings.HasPrefix(name, "CI_"))
	}
	if vars := parser.FindKey(job, "variables"); vars != nil && vars.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(vars.Content); i += 2 {
			if secret(strings.ToUpper(vars.Content[i].Value)) {
				return true
			}
		}
	}
	for _, line := range CollectJobScriptLines(job) {
		for _, loc := range gl021VarRefRe.FindAllStringSubmatchIndex(line.Value, -1) {
			if secret(line.Value[loc[2]:loc[3]]) {
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

// gl013Owns reports whether GL013 already flags this job (a production-like
// environment or the main Pages site, with no rules:/only: restriction), so
// GL080 can defer to it.
// gl013OwnsOpen reports a production deploy whose open rules: entry GL013
// reports (#1490), so GL080 doesn't report the same entry again.
func gl013OwnsOpen(job *yaml.Node) bool {
	env := parser.FindKey(job, "environment")
	if env == nil {
		return false
	}
	return isProductionOnly(extractEnvName(env), extractDeploymentTier(env)) && deploysToEnvironment(env)
}

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

// gl080ScriptDeploys is jobScriptDeploys without the commands that ship
// nothing another branch depends on (#1492): a container image pushed under a
// tag made from the branch, commit, pipeline, job or merge request, and a
// publish or apply in dry-run mode. A push of latest, a fixed tag or a
// version still counts, since any branch can overwrite what others pull.
// discounted reports a deploy command that one of these exceptions or a
// guard in the script took out. strong reports that a deploy is a registry,
// package, infra or release command, not only a weak signal (#1548).
func gl080ScriptDeploys(in *Inheritance, job, globalVars *yaml.Node) (deploys, strong, discounted bool) {
	jobVars := parser.FindKey(job, "variables")
	flags := protectedFlags(in, job, globalVars)
	lines := CollectJobScriptLines(job)
	local := createsLocalCluster(lines)
	hosts := serviceHosts(job)
	// after_script runs in a shell of its own, so an exit in the script
	// doesn't end it.
	var after map[*yaml.Node]bool
	if as := parser.FindKey(job, "after_script"); as != nil && as.Kind == yaml.SequenceNode {
		after = map[*yaml.Node]bool{}
		for _, l := range as.Content {
			after[l] = true
		}
	}
	// Each value a script variable is assigned outside a guarded step,
	// starting with the values rules:variables give it on unprotected refs.
	shellVars := unprotectedRuleValues(in, job, globalVars)
	exited, weak := false, false
	for _, line := range lines {
		if lineDeploys(line.Value) {
			discounted = true
		}
		if exited && !after[line] {
			continue
		}
		text := blankGuardedSteps(line.Value, flags)
		if !after[line] {
			if at := exitGuardAt(line.Value, flags); at >= 0 {
				// The commands before the guard still run on every ref.
				text, exited = text[:at], true
			}
		}
		for _, cmd := range shellCommands(text) {
			if m := shellAssignRe.FindStringSubmatch(stripShellKeywords(cmd.text)); m != nil {
				if shellVars == nil {
					shellVars = map[string][]string{}
				}
				shellVars[m[1]] = append(shellVars[m[1]], strings.Trim(strings.TrimSpace(m[2]), `"'`))
			}
		}
		if !lineDeploys(text) {
			continue
		}
		rest := text
		for _, cmd := range shellCommands(blankShellComments(text)) {
			words := stripExecWrapper(commandWords(cmd.text))
			if dryRun(words) || ephemeralImagePush(words, jobVars, globalVars, shellVars) || ephemeralPackageUpload(words, jobVars, globalVars, shellVars) || ephemeralCopy(words, jobVars, globalVars, shellVars) || ephemeralChartPush(words, lines, jobVars, globalVars, shellVars) || local && (clusterCommand(words) || deployVerbRunners[commandName(words)]) {
				rest = strings.Replace(rest, cmd.text, "", 1)
			}
		}
		if lineDeploys(rest) && (strongDeploy(rest) || !publishesToService(job, rest, lines, hosts)) {
			if strongSignal(rest) {
				return true, true, false
			}
			weak = true
		}
	}
	if weak {
		return true, false, false
	}
	return false, false, discounted
}

// strongSignal reports a command on the line that ships to a registry, a
// package index or infrastructure, or cuts a release: the commands of
// deployCmdRe and releaseCmdRe other than the copy and push tools (rsync, scp,
// rclone, git push), which often ship nothing shared, such as a local path, a
// per-run directory or a results repository (#1548).
func strongSignal(text string) bool {
	for _, cmd := range shellCommands(blankShellComments(text)) {
		if !lineDeploys(cmd.text) {
			continue
		}
		lower := strings.ToLower(cmd.text)
		if releaseCmdRe.MatchString(lower) {
			return true
		}
		for _, m := range deployCmdRe.FindAllStringIndex(lower, -1) {
			if !copyOrPushRe.MatchString(lower[m[0]:m[1]]) {
				return true
			}
		}
	}
	return false
}

var copyOrPushRe = mustCompilePrefiltered(`^(?:[^0-9a-z_.-])?(?:rsync|scp)(?:\s|$)|^rclone\b|^git\s+push\b`)

// unprotectedRuleValues returns, for each variable that a workflow:rules or job
// rules: entry sets, the values it can hold on an unprotected ref: those of
// the entries that don't restrict to protected refs, and its variables:
// default, which applies when no entry sets it. A per-branch tag set only for
// other branches (TAG: $CI_COMMIT_REF_SLUG next to TAG: latest for the
// default branch) then reads as per run.
func unprotectedRuleValues(in *Inheritance, job, globalVars *yaml.Node) map[string][]string {
	var vals map[string][]string
	var sources []*yaml.Node
	if wf := parser.FindKey(in.mapping, "workflow"); wf != nil {
		sources = append(sources, parser.FindKey(wf, "rules"))
	}
	sources = append(sources, parser.FindKey(job, "rules"))
	for _, rules := range sources {
		if rules == nil || rules.Kind != yaml.SequenceNode {
			continue
		}
		for _, item := range rules.Content {
			v := parser.FindKey(item, "variables")
			if v == nil || v.Kind != yaml.MappingNode || ruleExcludes(item) {
				continue
			}
			cond := parser.FindKey(item, "if")
			if cond != nil && cond.Kind == yaml.ScalarNode && ifRestrictsToProtected(cond.Value) {
				if vals == nil {
					vals = map[string][]string{}
				}
				for i := 0; i+1 < len(v.Content); i += 2 {
					if _, ok := vals[v.Content[i].Value]; !ok {
						vals[v.Content[i].Value] = nil
					}
				}
				continue
			}
			for i := 0; i+1 < len(v.Content); i += 2 {
				if vals == nil {
					vals = map[string][]string{}
				}
				vals[v.Content[i].Value] = append(vals[v.Content[i].Value], v.Content[i+1].Value)
			}
		}
	}
	if vals == nil {
		return nil
	}
	defaults := literalVariables(globalVars)
	for k, d := range literalVariables(parser.FindKey(job, "variables")) {
		defaults[k] = d
	}
	for name, vs := range vals {
		if d, ok := defaults[name]; ok {
			vs = append(vs, d)
		}
		if len(vs) == 0 {
			// Set only on protected refs: elsewhere it is empty.
			vs = []string{""}
		}
		vals[name] = vs
	}
	return vals
}

// stripShellKeywords drops the then/else/do keywords in front of a command.
func stripShellKeywords(text string) string {
	for {
		t := strings.TrimLeft(text, " \t")
		cut := false
		for _, kw := range [...]string{"then", "else", "do"} {
			if rest, ok := strings.CutPrefix(t, kw); ok && (rest == "" || rest[0] == ' ' || rest[0] == '\t') {
				text, cut = rest, true
				break
			}
		}
		if !cut {
			return t
		}
	}
}

// strongDeploy reports a line with a deploy command glsec reads as one, not
// only a bare deploy/publish verb or a deploy script.
func strongDeploy(text string) bool {
	lower := strings.ToLower(blankShellComments(text))
	return deployCmdRe.MatchString(lower) || releaseCmdRe.MatchString(lower)
}

// serviceHosts returns the host names of the job's services: containers, or
// nil when it has none.
func serviceHosts(job *yaml.Node) map[string]bool {
	svc := parser.FindKey(job, "services")
	if svc == nil || svc.Kind != yaml.SequenceNode || len(svc.Content) == 0 {
		return nil
	}
	hosts := map[string]bool{"localhost": true, "127.0.0.1": true}
	for _, s := range svc.Content {
		image := s.Value
		if s.Kind == yaml.MappingNode {
			if a := parser.FindKey(s, "alias"); a != nil {
				for _, al := range strings.Split(a.Value, ",") {
					hosts[strings.ToLower(strings.TrimSpace(al))] = true
				}
			}
			image = ""
			if n := parser.FindKey(s, "name"); n != nil {
				image = n.Value
			}
		}
		repo := imageRepository(image)
		if i := strings.LastIndexByte(repo, '/'); i >= 0 {
			repo = repo[i+1:]
		}
		hosts[strings.ToLower(repo)] = true
	}
	return hosts
}

// publishesToService reports a bare deploy verb or script that seeds one of
// the job's own service containers: the line itself names a service URL, or
// an earlier line points a remote, URL or registry setting at one, the job
// carries no credential, and no URL in the job leaves its services.
func publishesToService(job *yaml.Node, line string, lines []*yaml.Node, hosts map[string]bool) bool {
	if hosts == nil {
		return false
	}
	onService := func(text string) (any, other bool) {
		for _, m := range urlHostRe.FindAllStringSubmatch(text, -1) {
			if hosts[strings.ToLower(m[1])] {
				any = true
			} else {
				other = true
			}
		}
		return any, other
	}
	if any, other := onService(line); other {
		return false
	} else if any {
		return true
	}
	configured := false
	for _, l := range lines {
		any, other := onService(l.Value)
		if other {
			return false
		}
		lower := strings.ReplaceAll(strings.ToLower(l.Value), "curl", "")
		if any && (strings.Contains(lower, "remote") || strings.Contains(lower, "url") || strings.Contains(lower, "registry") || strings.Contains(lower, "endpoint")) {
			configured = true
		}
	}
	return configured && !jobUsesCredential(job, false)
}

// urlHostRe matches an http(s) URL's host.
var urlHostRe = mustCompilePrefiltered(`https?://(?:[^/@\s]*@)?([A-Za-z0-9._$-]+)`)

// createsLocalCluster reports a job that starts a throwaway Kubernetes cluster
// of its own (kind, k3d, minikube), as chart tests do: its kubectl and helm
// commands then talk to that cluster, not to a deployment.
func createsLocalCluster(lines []*yaml.Node) bool {
	for _, line := range lines {
		v := line.Value
		if strings.Contains(v, "kind create cluster") || strings.Contains(v, "k3d cluster create") || strings.Contains(v, "minikube start") || strings.Contains(v, "ctlptl create cluster") {
			return true
		}
	}
	return false
}

func clusterCommand(words []string) bool {
	switch commandName(words) {
	case "kubectl", "helm":
		return true
	}
	return false
}

// perRunTagVars name a branch, commit, pipeline, job or merge request; an
// image tag built from one is new for each of them.
var perRunTagVars = []string{
	"CI_COMMIT_REF_SLUG", "CI_COMMIT_REF_NAME", "CI_COMMIT_BRANCH",
	"CI_COMMIT_SHA", "CI_COMMIT_SHORT_SHA", "CI_PIPELINE_ID", "CI_PIPELINE_IID",
	"CI_JOB_ID", "CI_MERGE_REQUEST_IID",
}

// ephemeralImagePush reports a docker, podman, buildah or nerdctl push of one
// image whose tag or repository names the run (perRunTagVars). Variables in the image are
// expanded through the job's and the file's variables:, so "$IMG-debug" with
// IMG ending in :$CI_PIPELINE_ID counts.
func ephemeralImagePush(words []string, jobVars, globalVars *yaml.Node, shellVars map[string][]string) bool {
	switch commandName(words) {
	case "docker", "podman", "buildah", "nerdctl":
	default:
		return false
	}
	i := 1
	if i < len(words) && words[i] == "image" {
		i++
	}
	if i >= len(words) || words[i] != "push" {
		return false
	}
	// podman and buildah push SOURCE [DESTINATION]: every operand must be per
	// run, or the push writes a shared one.
	var images []string
	for _, w := range words[i+1:] {
		if w == "--all-tags" || w == "-a" {
			return false
		}
		if !strings.HasPrefix(w, "-") {
			images = append(images, w)
		}
	}
	if len(images) == 0 {
		return false
	}
	for _, image := range images {
		if !perRunValue(image, jobVars, globalVars, shellVars) {
			return false
		}
	}
	return true
}

// ephemeralPackageUpload reports a curl upload to the GitLab package
// registry (#1538) whose package name, version or file names the run, as
// ephemeralImagePush does for an image: another branch can't write to it.
func ephemeralPackageUpload(words []string, jobVars, globalVars *yaml.Node, shellVars map[string][]string) bool {
	if commandName(words) != "curl" {
		return false
	}
	for _, w := range words[1:] {
		w = strings.Trim(w, `"'`)
		if _, path, ok := strings.Cut(strings.ToLower(w), "/packages/"); ok {
			return perRunValue(w[len(w)-len(path):], jobVars, globalVars, shellVars)
		}
	}
	return false
}

// ephemeralCopy reports an scp or rsync to a remote directory that names the
// run (scp out.tar ci@host:/srv/cache/$CI_PIPELINE_ID), as ephemeralImagePush
// does for an image: no other branch reads or writes it.
func ephemeralCopy(words []string, jobVars, globalVars *yaml.Node, shellVars map[string][]string) bool {
	switch commandName(words) {
	case "scp", "rsync":
	default:
		return false
	}
	// The flags that take a separate value (scp -P 2222, rsync -e ssh).
	valued := map[string]bool{"-c": true, "-F": true, "-i": true, "-J": true, "-l": true, "-o": true, "-P": true, "-S": true}
	if commandName(words) == "rsync" {
		valued = map[string]bool{"-e": true}
	}
	dest := ""
	for i := 1; i < len(words); i++ {
		switch w := words[i]; {
		case valued[w]:
			i++
		case strings.HasPrefix(w, "-"):
		default:
			dest = w
		}
	}
	host, path, ok := strings.Cut(strings.Trim(dest, `"'`), ":")
	if !ok || host == "" || strings.Contains(host, "/") || path == "" {
		return false
	}
	return perRunValue(path, jobVars, globalVars, shellVars)
}

// ephemeralChartPush reports a helm push or cm-push of a chart whose version
// names the run (#1524), as ephemeralImagePush does for an image: the push
// sets a per-run --version, or it pushes a packaged .tgz and every helm
// package in the job sets one. Without --version, helm package takes the
// version from Chart.yaml, which every branch shares.
func ephemeralChartPush(words []string, lines []*yaml.Node, jobVars, globalVars *yaml.Node, shellVars map[string][]string) bool {
	if commandName(words) != "helm" || len(words) < 3 || words[1] != "push" && words[1] != "cm-push" {
		return false
	}
	if v, ok := argValue(words[2:], "--version"); ok {
		return perRunValue(v, jobVars, globalVars, shellVars)
	}
	if !strings.Contains(words[2], ".tgz") {
		return false
	}
	packaged := false
	for _, line := range lines {
		for _, cmd := range shellCommands(blankShellComments(line.Value)) {
			w := commandWords(cmd.text)
			if commandName(w) != "helm" || len(w) < 2 || w[1] != "package" {
				continue
			}
			v, ok := argValue(w[2:], "--version")
			if !ok || !perRunValue(v, jobVars, globalVars, shellVars) {
				return false
			}
			packaged = true
		}
	}
	return packaged
}

// argValue returns the value of a --flag=value or --flag value argument.
func argValue(args []string, flag string) (string, bool) {
	for i, a := range args {
		if v, ok := strings.CutPrefix(a, flag+"="); ok {
			return v, true
		}
		if a == flag && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

// perRunValue reports whether value, with its variables expanded through the
// job's and the file's variables: and the script's assignments, names the run
// (perRunImage) whatever value the script gave each variable.
func perRunValue(value string, jobVars, globalVars *yaml.Node, shellVars map[string][]string) bool {
	value = strings.Trim(value, `"'`)
	candidates := []string{value}
	var vars map[string]string
	if strings.Contains(value, "$") {
		vars = literalVariables(globalVars)
		for k, v := range literalVariables(jobVars) {
			vars[k] = v
		}
		for k, vs := range shellVars {
			vars[k] = vs[len(vs)-1]
		}
		// A variable the script assigns more than once may hold any of its
		// values.
		for name, vs := range shellVars {
			if len(vs) < 2 || !mentionsVar(value, name) || len(candidates)*len(vs) > 16 {
				continue
			}
			var next []string
			for _, c := range candidates {
				for _, v := range vs {
					next = append(next, replaceRefs(c, func(ref string) string {
						if strings.Trim(ref, "${}") == name {
							return v
						}
						return ref
					}))
				}
			}
			candidates = next
		}
	}
	for _, c := range candidates {
		if !perRunImage(expandVars(c, vars, "", 0)) {
			return false
		}
	}
	return true
}

// perRunImage reports an image whose repository or tag names the run
// ($CI_REGISTRY_IMAGE/build-$CI_COMMIT_REF_SLUG, :$CI_COMMIT_SHA).
func perRunImage(image string) bool {
	for _, v := range perRunTagVars {
		if strings.Contains(image, "$"+v) || strings.Contains(image, "${"+v+"}") {
			return true
		}
	}
	return commitDerived(image)
}

// commitDerivedRe matches a command substitution that prints the commit:
// git rev-parse HEAD, git describe (tag-count-gSHA, unless --abbrev=0 cuts
// it to the last tag every later commit shares).
var commitDerivedRe = mustCompilePrefiltered("(?:\\$\\(|`)\\s*git\\s+(?:rev-parse\\b[^)`]*\\bHEAD\\b|describe\\b[^)`]*)")

func commitDerived(s string) bool {
	for _, m := range commitDerivedRe.FindAllStringSubmatch(s, -1) {
		if !strings.Contains(m[0], "--abbrev=0") {
			return true
		}
	}
	return false
}

// dryRun reports a command run in dry-run mode, which changes nothing:
// --dry-run (kubectl's --dry-run=none is a real run) or dart's pub publish -n.
func dryRun(words []string) bool {
	pub := false
	for i, w := range words {
		switch {
		case w == "--dry-run":
			return true
		case strings.HasPrefix(w, "--dry-run="):
			return strings.TrimPrefix(w, "--dry-run=") != "none"
		case w == "pub" && i+1 < len(words) && words[i+1] == "publish":
			pub = true
		case pub && w == "-n":
			return true
		}
	}
	return false
}

// ephemeralEnvironmentIn reports an environment that on its own says nothing
// about a deploy another branch depends on (#1497): one whose tier is
// development or testing (deployment_tier:, else GitLab's guess from the
// name), or whose name is made per branch, commit, pipeline or merge request
// (review/$CI_COMMIT_REF_SLUG). A per-run name GitLab guesses as production
// (prod/$CI_COMMIT_REF_SLUG) still counts. The job stays sensitive through
// its script or a deploy name with a credential.
// The name is expanded through the job's and the file's variables:
// (ENV_NAME: review/$CI_COMMIT_REF_SLUG, also set by the matching rules:
// entry).
func ephemeralEnvironmentIn(env, jobVars, globalVars *yaml.Node) bool {
	name := extractEnvName(env)
	tier, explicit := envTier(env)
	if !explicit && strings.Contains(name, "$") && (jobVars != nil || globalVars != nil) {
		vars := literalVariables(globalVars)
		for k, v := range literalVariables(jobVars) {
			vars[k] = v
		}
		if expanded := expandVars(name, vars, "", 0); expanded != name {
			name = expanded
			tier, _ = envTier(&yaml.Node{Kind: yaml.ScalarNode, Value: name})
		}
	}
	switch tier {
	case "development", "testing":
		return true
	case "production":
		return false
	}
	for _, v := range perRunTagVars {
		if strings.Contains(name, "$"+v) || strings.Contains(name, "${"+v+"}") {
			return true
		}
	}
	return false
}

// gl080EntryLabel names a rules: entry without if: by what it has instead.
func gl080EntryLabel(entry *yaml.Node) string {
	if cond := parser.FindKey(entry, "if"); cond != nil && cond.Kind == yaml.ScalarNode {
		return "(if: " + cond.Value + ", true in every child pipeline the trigger job starts on any branch)"
	}
	for _, key := range []string{"changes", "exists"} {
		if parser.FindKey(entry, key) != nil {
			return "without if: (" + key + ":)"
		}
	}
	if w := parser.FindKey(entry, "when"); w != nil && w.Kind == yaml.ScalarNode {
		return "without if: (when: " + w.Value + ")"
	}
	return "without if: (no condition)"
}
