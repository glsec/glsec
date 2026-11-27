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

type gl017 struct{}

var GL017 = &gl017{}

func (r *gl017) ID() string { return "GL017" }

// deployStageKeywords identifies stages that indicate deployment activity.
var deployStageKeywords = []string{"deploy", "release", "publish", "ship"}

// deployCmdRe matches commands that ship or publish to an external target as
// adjacent tokens (docker push, kubectl apply), so a match is a real command,
// not a word in a comment, a path, or a flag. The bare verbs deploy/publish and
// the snapshot-capable release tools are handled separately, in command
// position, so `# build for deploy`, `deploy/compose.yml` or
// `--no-check-publish` no longer read as a deployment (#1096, release FP scan).
var deployCmdRe = mustCompilePrefiltered(
	`(?:docker|podman|buildah|crane|skopeo|nerdctl|ko)\s+push\b` +
		`|helm\s+(?:push|cm-push|upgrade|install)\b` +
		`|twine\s+upload\b|cargo\s+publish\b|(?:npm|yarn|pnpm)\s+publish\b|gem\s+push\b|dotnet\s+nuget\s+push\b|(?:uv|flit|poetry|maturin)\s+(?:publish|upload)\b` +
		`|kubectl\s+(?:apply|rollout|set|create|patch|replace)\b|(?:^|[^0-9a-z_.-])(?:kustomize|argocd)\b|skaffold\s+(?:run|deploy)\b` +
		`|aws\s+(?:s3|deploy|ecs|lambda|cloudformation|elasticbeanstalk|amplify|cloudfront)\b|gcloud\s+(?:app|run|functions|compute|container|storage)\b|az\s+(?:webapp|functionapp|aks|acr|storage)\b|flyctl?\s+deploy\b|netlify[^|;&]*deploy\b|(?:^|[^0-9a-z_.-])vercel\b|railway\s+up\b` +
		`|serverless\s+deploy\b|sls\s+deploy\b|terraform\s+apply\b|pulumi\s+up\b|ansible-playbook\b|cap\s+\S+\s+deploy\b|mina\s+deploy\b|(?:^|[^0-9a-z_.-])fastlane\b` +
		`|(?:^|[^0-9a-z_.-])(?:rsync|scp)(?:\s|$)|rclone\b|git\s+push\b` +
		// curl --upload-file/-T to a project's GitLab package registry
		// (#1538), in either order of flag and URL. Other upload targets
		// (reports, webhooks, scratch buckets) are left out.
		`|\bcurl\b[^|;&]*?(?:--upload-file|\s-[a-z]{0,5}t)\s[^|;&]*?` + gitlabPackagesURL +
		`|\bcurl\b[^|;&]*?` + gitlabPackagesURL + `[^|;&]*?(?:--upload-file|\s-[a-z]{0,5}t)\s`,
)

// gitlabPackagesURL matches a lowercased GitLab package registry API path of
// a project.
const gitlabPackagesURL = `(?:/api/v4|ci_api_v4_url\}?)/projects/\S*?/packages/`

// releaseCmdRe matches release tools that publish but also run in a local
// snapshot or skip-publish mode; a match counts only when the line does not opt
// out of publishing (goreleaser release --snapshot ships nothing).
var releaseCmdRe = mustCompilePrefiltered(
	`goreleaser\s+release\b|gh\s+release\s+(?:create|upload)\b|glab\s+release\b|release-cli\s+create\b|semantic-release(?:[^\w.-]|$)`,
)

// deployVerbRe matches a bare deploy/publish verb as its own word: make deploy,
// a /deploy webhook URL, deploy@host. The boundaries exclude a flag
// (--no-check-publish), a directory prefix (deploy/compose.yml) and a filename
// or compound word (publish.el, docker-kubernetes-deploy), so only a standalone
// verb counts. A deploy/publish script whose extension hides it here
// (./deploy.sh) is caught in command position by runsDeployScript.
var deployVerbRe = mustCompilePrefiltered(
	`(?:^|[^0-9a-z._-])(?:deploy|publish)(?:$|[^0-9a-z._/-])`,
)

// jobScriptDeploys reports whether the job's effective script (its own and any
// inherited via extends:) runs a command that ships or publishes something.
func jobScriptDeploys(in *Inheritance, job *yaml.Node) bool {
	for _, line := range CollectJobScriptLines(in.Effective(job)) {
		if lineDeploys(line.Value) {
			return true
		}
	}
	return false
}

// lineDeploys reports whether one script line runs a deploy or publish command.
// Comments are blanked first, so a verb in `# build for deploy` is not read as a
// command; a here-document body kept by blankShellComments still matches a real
// remote command.
func lineDeploys(raw string) bool {
	code := blankShellComments(raw)
	lower := strings.ToLower(code)
	// echo/printf only print text unless piped into a shell, so drop their
	// arguments before the line-level match for the adjacent-token commands.
	for _, cmd := range shellCommands(code) {
		if cmd.piped {
			continue
		}
		// `bundle exec fastlane test` is a fastlane invocation; classify by the
		// wrapped command, not the wrapper, so the lane logic below can see it.
		w := stripExecWrapper(commandWords(cmd.text))
		if helpOnly(w) || psWrite(w) {
			lower = strings.Replace(lower, strings.ToLower(cmd.text), "", 1)
			continue
		}
		switch commandName(w) {
		case "rsync", "scp":
			// A copy between local paths ships nothing (rsync -a ~/.cache home/).
			if localRsync(w) {
				lower = strings.Replace(lower, strings.ToLower(cmd.text), "", 1)
			}
		case "fdroid":
			// fdroid publish signs the built APKs into the local repo/
			// directory; fdroid deploy is what uploads it.
			if len(w) >= 2 && w[1] == "publish" {
				lower = strings.Replace(lower, strings.ToLower(cmd.text), "", 1)
			}
		case "pixi":
			// pixi publish uploads only with a target channel; without one it
			// copies the built package into a local directory.
			if len(w) >= 2 && w[1] == "publish" && !hasFlag(w, "--to", "--target-channel") {
				lower = strings.Replace(lower, strings.ToLower(cmd.text), "", 1)
			}
		case "echo", "printf":
			lower = strings.Replace(lower, strings.ToLower(cmd.text), "", 1)
		case "cd", "pushd":
			// A directory name says nothing about what runs there
			// (cd "Deploy de uma app", #1527).
			lower = strings.Replace(lower, strings.ToLower(cmd.text), "", 1)
		case "dotnet":
			// `dotnet publish` builds and writes output locally; only `dotnet
			// nuget push` ships to a registry (matched by deployCmdRe). Drop the
			// local publish so the bare verb does not read it as a deployment.
			if len(w) >= 2 && strings.EqualFold(w[1], "publish") {
				lower = strings.Replace(lower, strings.ToLower(cmd.text), "", 1)
			}
		case "ansible-playbook":
			// --syntax-check parses the play locally and --list-tasks/
			// --list-hosts/--list-tags only enumerate it; none connects to a
			// host or changes state, so they deploy nothing. Check mode
			// (--check/-C) still connects with credentials, so it is left in.
			if ansibleLocalOnly(w) {
				lower = strings.Replace(lower, strings.ToLower(cmd.text), "", 1)
			}
		case "fastlane":
			// fastlane lanes are user-defined, so a bare `fastlane` is not a
			// deploy by itself. Drop it only when the lane is a known build/test
			// action (fastlane test, scan, build_app, update_fastlane). A known
			// store action (deliver, supply, pilot, upload_to_*) or any other
			// lane name (ios, a custom deploy lane) stays a deploy signal.
			if fastlaneNonDeploy(w) {
				lower = strings.Replace(lower, strings.ToLower(cmd.text), "", 1)
			}
		default:
			// a package manager installing packages: deploy-tool names in its
			// argument list (rsync, openssh-client, ansible, terraform, vercel…)
			// are packages being installed, not commands being run, so they do
			// not deploy. `apt-get install rsync && rsync -av host:` keeps the
			// real rsync, which is a separate shell command.
			if isPackageInstall(w) {
				lower = strings.Replace(lower, strings.ToLower(cmd.text), "", 1)
			}
		}
	}
	if deployCmdRe.MatchString(lower) {
		return true
	}
	// The snapshot flag counts wherever the line sets it, also through a
	// command substitution whose echo was dropped above
	// (goreleaser release $([ -z "$CI_COMMIT_TAG" ] && echo --snapshot)).
	if releaseCmdRe.MatchString(lower) &&
		!strings.Contains(strings.ToLower(code), "--snapshot") && !skipsPublish(lower) {
		return true
	}
	if deployVerbRe.MatchString(lower) && !skipsPublish(lower) {
		return true
	}
	for _, cmd := range shellCommands(code) {
		if !cmd.piped && runsDeployScript(cmd) {
			return true
		}
	}
	return false
}

// psWrite reports a PowerShell cmdlet that only prints its arguments, as echo
// does (Write-Output "Will run deploy command", #1524).
func psWrite(w []string) bool {
	if len(w) == 0 {
		return false
	}
	switch strings.ToLower(w[0]) {
	case "write-output", "write-host", "write-information", "write-verbose":
		return true
	}
	return false
}

// helpOnly reports a command that only prints its usage: --help anywhere, or
// -h or help as its last word (mytool deploy -h).
func helpOnly(w []string) bool {
	if len(w) < 2 {
		return false
	}
	if last := w[len(w)-1]; last == "-h" || last == "help" {
		return true
	}
	return hasFlag(w, "--help")
}

// hasFlag reports whether w has one of the flags, alone or as --flag=value.
func hasFlag(w []string, flags ...string) bool {
	for _, a := range w[1:] {
		for _, f := range flags {
			if a == f || strings.HasPrefix(a, f+"=") {
				return true
			}
		}
	}
	return false
}

// ansibleLocalOnly reports whether an ansible-playbook invocation only parses or
// enumerates the play locally (--syntax-check, --list-tasks/--list-hosts/
// --list-tags) and so connects to no host and deploys nothing. Check mode
// (--check/-C) still connects with credentials and is deliberately not listed.
func ansibleLocalOnly(w []string) bool {
	for _, a := range w[1:] {
		switch strings.ToLower(a) {
		case "--syntax-check", "--list-tasks", "--list-hosts", "--list-tags":
			return true
		}
	}
	return false
}

// fastlaneDeployActions are built-in fastlane actions/lanes that ship to a store
// or distribution channel; any of them keeps the invocation a deploy signal.
var fastlaneDeployActions = map[string]bool{
	"deliver": true, "supply": true, "pilot": true, "match": true,
	"appstore": true, "playstore": true, "deploy": true, "release": true,
	"pod_push": true, "push_to_git_remote": true,
	"upload_to_app_store": true, "upload_to_play_store": true,
	"upload_to_testflight": true, "set_github_release": true,
}

// fastlaneNonDeployActions are built-in fastlane actions/lanes that only build,
// test or maintain tooling locally and ship nothing.
var fastlaneNonDeployActions = map[string]bool{
	"test": true, "tests": true, "unit_test": true, "unit_tests": true,
	"lint": true, "build": true, "scan": true, "run_tests": true,
	"build_app": true, "gym": true, "snapshot": true, "screengrab": true,
	"update_fastlane": true,
}

// fastlaneNonDeploy reports whether a `fastlane` invocation runs only a known
// build/test lane and so deploys nothing. A known store action anywhere on the
// line keeps it a deploy; otherwise the operative lane (the last positional
// token, after an optional ios/android/mac platform) must be a known non-deploy
// action. Any unknown lane name is left as a deploy signal.
func fastlaneNonDeploy(w []string) bool {
	var pos []string
	for _, a := range w[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		pos = append(pos, strings.ToLower(a))
	}
	if len(pos) == 0 {
		return false
	}
	for _, p := range pos {
		if fastlaneDeployActions[p] {
			return false
		}
	}
	return fastlaneNonDeployActions[pos[len(pos)-1]]
}

// pkgInstallers are package managers whose install subcommand takes package
// names as arguments.
var pkgInstallers = map[string]bool{
	"apt-get": true, "apt": true, "aptitude": true, "apk": true,
	"yum": true, "dnf": true, "microdnf": true, "zypper": true,
	"pip": true, "pip3": true, "pipx": true, "brew": true, "gem": true,
	"npm": true, "yarn": true, "pnpm": true,
}

// isPackageInstall reports whether the command installs packages, so its
// positional arguments are package names rather than commands to run. It keys
// off the program plus its install subcommand (install/add/i/in), so
// `apt-get install rsync`, `apk add openssh-client`, `pip install ansible` and
// `gem install fastlane` are installs, while `npm run deploy` is not.
func isPackageInstall(w []string) bool {
	if len(w) < 2 || !pkgInstallers[strings.ToLower(commandName(w))] {
		return false
	}
	for _, a := range w[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		switch strings.ToLower(a) {
		case "install", "add", "i", "in":
			return true
		}
		return false
	}
	return false
}

// stripExecWrapper removes a leading `bundle exec` / `bundler exec` (optionally
// a pinned-version token, `bundle _2.4.1_ exec`) so the wrapped command is
// classified by its own name — `bundle exec fastlane deploy` is a fastlane run,
// not a `bundle` run. Returns w unchanged when there is no such wrapper.
func stripExecWrapper(w []string) []string {
	w = stripRunPrefix(w)
	if len(w) < 3 {
		return w
	}
	n := strings.ToLower(w[0])
	if n != "bundle" && n != "bundler" {
		return w
	}
	i := 1
	if strings.HasPrefix(w[i], "_") && strings.HasSuffix(w[i], "_") {
		i++
	}
	if i+1 < len(w) && strings.EqualFold(w[i], "exec") {
		return w[i+1:]
	}
	return w
}

// stripRunPrefix drops the commands that only run another one: time, nohup,
// sudo (with its flags), env with its assignments, timeout and nice with
// their arguments (time curl --upload-file …).
func stripRunPrefix(w []string) []string {
	for len(w) > 1 {
		switch strings.ToLower(w[0]) {
		case "time", "nohup", "command", "exec":
			w = w[1:]
		case "sudo":
			i := 1
			for i < len(w) && strings.HasPrefix(w[i], "-") {
				if w[i] == "-u" || w[i] == "-g" {
					i++
				}
				i++
			}
			w = w[min(i, len(w)):]
		case "env":
			i := 1
			for i < len(w) && (strings.HasPrefix(w[i], "-") || strings.Contains(w[i], "=")) {
				i++
			}
			w = w[min(i, len(w)):]
		case "timeout", "nice":
			i := 1
			for i < len(w) && strings.HasPrefix(w[i], "-") {
				// nice -n 5, timeout -s KILL / -k 5s take a value.
				if w[i] == "-n" || w[i] == "-s" || w[i] == "-k" {
					i++
				}
				i++
			}
			if strings.EqualFold(w[0], "timeout") && i < len(w) {
				i++ // the duration
			}
			w = w[min(i, len(w)):]
		default:
			return w
		}
	}
	return w
}

// skipsPublish reports whether a release command opts out of publishing.
func skipsPublish(lower string) bool {
	return strings.Contains(lower, "--skip publish") ||
		strings.Contains(lower, "--skip=publish") ||
		strings.Contains(lower, "--skip-publish")
}

// deployVerbRunners run a deploy/publish target by name (make container-publish,
// npm run deploy, task xray-publish). Only for these is a non-flag argument that
// names a deploy/publish target counted, so a deploy/publish word elsewhere on
// the line (a path, a flag, a filename) does not.
var deployVerbRunners = map[string]bool{
	"make": true, "rake": true, "task": true, "just": true, "invoke": true,
	"mage": true, "mix": true, "gulp": true, "grunt": true, "nx": true,
	"turbo": true, "lerna": true, "npm": true, "yarn": true, "pnpm": true,
	"bun": true, "hugo": true, "firebase": true, "wrangler": true,
	"eb": true, "sam": true, "surge": true, "heroku": true,
}

// runsDeployScript reports whether a command runs a deploy/publish that
// deployVerbRe cannot see: a program whose name is a deploy/publish script
// (./deploy.sh, deploy-staging.sh; or the script a shell runs, bash deploy.sh),
// or a task runner invoking a deploy/publish target whose name is compound
// (make container-publish, task xray-publish).
func runsDeployScript(cmd shellCommand) bool {
	w := commandWords(cmd.text)
	if len(w) == 0 {
		return false
	}
	name := strings.ToLower(commandName(w))
	if isDeployStem(name) {
		return true
	}
	// PowerShell keeps a backslash that the POSIX word split drops.
	if f := strings.Fields(cmd.text); strings.Contains(f[0], `\`) && isDeployStem(f[0]) {
		return true
	}
	switch name {
	case "sh", "bash", "zsh", "ash", "dash", "ksh":
		for _, a := range w[1:] {
			if strings.HasPrefix(a, "-") {
				continue
			}
			return isDeployStem(a)
		}
		return false
	}
	if deployVerbRunners[name] {
		for _, a := range w[1:] {
			if name == "bun" && (a == "-e" || a == "--eval" || a == "--print") {
				// The next word is code to run, not a target.
				return false
			}
			if strings.HasPrefix(a, "-") {
				continue
			}
			la := strings.ToLower(a)
			if la == "run" || la == "run-s" || la == "run-p" {
				continue
			}
			return runnerTargetDeploys(la)
		}
	}
	return false
}

// runnerTargetDeploys reports a task-runner target that names a deploy or
// publish: a word of it starts with deploy or publish (container-publish,
// build-and-deploy, deploy:prod, deployer:upload), and no word says it only
// reports, tests or inspects (deployment-info prints, xray-publish uploads
// test results, deploy-status checks one) (#1546).
func runnerTargetDeploys(target string) bool {
	parts := strings.FieldsFunc(target, func(r rune) bool { return (r < 'a' || r > 'z') && (r < '0' || r > '9') })
	deploys := false
	for _, p := range parts {
		if strings.HasPrefix(p, "deploy") || strings.HasPrefix(p, "publish") {
			deploys = true
		}
		switch p {
		case "test", "tests", "check", "verify", "lint", "info", "status", "help", "list", "show", "get", "diff", "plan", "xray", "report", "reports", "results", "coverage":
			return false
		}
	}
	return deploys
}

// isDeployStem reports whether a program or script name is a deploy/publish
// script: exactly deploy/publish, or prefixed (deploy-staging, publish_docs),
// with any directory and extension removed.
func isDeployStem(name string) bool {
	name = strings.ToLower(name)
	// A Windows runner's path uses backslashes (.\CICD\publish.ps1).
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	if i := strings.LastIndexByte(name, '.'); i > 0 {
		name = name[:i]
	}
	for _, v := range [2]string{"deploy", "publish"} {
		if name == v || strings.HasPrefix(name, v+"-") || strings.HasPrefix(name, v+"_") {
			return !testsDeploy(name)
		}
	}
	return false
}

// testsDeploy reports a script name that also says it tests or checks
// (deploy-image-test, publish_check): it verifies a deploy rather than
// running one (#1524).
func testsDeploy(name string) bool {
	for _, part := range strings.FieldsFunc(name, func(r rune) bool { return r == '-' || r == '_' }) {
		switch part {
		case "test", "tests", "check", "verify", "lint":
			return true
		}
	}
	return false
}

func (r *gl017) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	in := NewInheritance(doc)

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		if !runsInheritedJob(in, name, job) || !isSensitiveJob(in, job, true) {
			return
		}
		// A trigger job starts a downstream pipeline and runs on no runner, so
		// tags: has nothing to restrict there.
		if in.Key(job, "trigger") != nil {
			return
		}
		tagsNode := in.Key(job, "tags")
		if tagsNode != nil && tagsNode.Kind == yaml.SequenceNode && len(tagsNode.Content) > 0 {
			return
		}
		findings = append(findings, finding.Finding{
			RuleID:   "GL017",
			Severity: finding.Warn,
			Job:      name.Value,
			Message: fmt.Sprintf(
				"job %q deploys or publishes but has no tags: — it can run on any available runner, including untrusted self-hosted runners",
				name.Value,
			),
			File: file,
			Line: name.Line,
			Col:  name.Column,
		})
	})

	return findings
}

// isSensitiveJob returns true for jobs that deploy to an environment or
// whose stage name suggests deployment/release activity.
// envAction returns the configured GitLab environment action, if any.
func envAction(env *yaml.Node) string {
	if env.Kind != yaml.MappingNode {
		return ""
	}
	a := parser.FindKey(env, "action")
	if a == nil {
		return ""
	}
	return a.Value
}

// envActionNoDeploy reports an environment: whose action deploys nothing:
// stop tears it down, while prepare, verify and access only use it.
func envActionNoDeploy(env *yaml.Node) bool {
	switch envAction(env) {
	case "prepare", "stop", "verify", "access":
		return true
	}
	return false
}

// envActionStops reports an environment action that tears the environment
// down. Unlike the other non-deploy actions, it is not a deploy even when the
// job is in a deploy-like stage.
func envActionStops(env *yaml.Node) bool {
	return envAction(env) == "stop"
}

// jobEnvTier is envTier for a job's environment, with a guessed name first
// expanded through the job's variables: (also from extends:) and the file's
// (#1528): GitLab expands the name before it guesses the tier.
func (in *Inheritance) jobEnvTier(job, env *yaml.Node) (tier string, explicit bool) {
	tier, explicit = envTier(env)
	name := extractEnvName(env)
	if explicit || !strings.Contains(name, "$") {
		return tier, explicit
	}
	vars := literalVariables(parser.FindKey(in.mapping, "variables"))
	for k, v := range literalVariables(parser.FindKey(in.Effective(job), "variables")) {
		vars[k] = v
	}
	if expanded := expandVars(name, vars, "", 0); expanded != name {
		// A variable the file doesn't set is unknown here: its name
		// ($NAMESPACE_dev) is not part of the environment's name.
		expanded = anyVarRefRe.ReplaceAllStringFunc(expanded, func(string) string { return "" })
		tier, _ = envTier(&yaml.Node{Kind: yaml.ScalarNode, Value: expanded})
	}
	return tier, false
}

var anyVarRefRe = mustCompilePrefiltered(`\$\{?[A-Za-z_][A-Za-z0-9_]*\}?`)

// jobEnvDevTier reports an environment that declares itself a review or test
// target: per-branch previews, links to job artifacts.
func (in *Inheritance) jobEnvDevTier(job, env *yaml.Node) bool {
	t, _ := in.jobEnvTier(job, env)
	return t == "development" || t == "testing"
}

// envTier returns an environment's deployment tier: its deployment_tier:,
// else the tier GitLab guesses from the name (Environment#guess_tier in
// GitLab's source, #989). explicit reports which.
func envTier(env *yaml.Node) (tier string, explicit bool) {
	name := ""
	switch env.Kind {
	case yaml.ScalarNode:
		name = env.Value
	case yaml.MappingNode:
		if t := parser.FindKey(env, "deployment_tier"); t != nil && t.Kind == yaml.ScalarNode {
			return t.Value, true
		}
		if n := parser.FindKey(env, "name"); n != nil && n.Kind == yaml.ScalarNode {
			name = n.Value
		}
	}
	for _, g := range tierGuesses {
		if g.re.MatchString(name) {
			return g.tier, false
		}
	}
	return "other", false
}

// tierGuesses are GitLab's guesses, in its order: a name matches the first.
var tierGuesses = []struct {
	tier string
	re   prefiltered
}{
	{"development", mustCompilePrefiltered(`(?i)(dev|review|trunk)`)},
	{"testing", mustCompilePrefiltered(`(?i)(test|tst|int|ac(ce|)pt|qa|qc|control|quality)`)},
	{"staging", mustCompilePrefiltered(`(?i)(st(a|)g|mod(e|)l|pre|demo|non)`)},
	{"production", mustCompilePrefiltered(`(?i)(pr(o|)d|live)`)},
}

// checkOnlyKeywords mark a job or stage that tests or checks rather than
// deploys, whatever else its name says: "deployment test", "check
// migrations", "release/gitleaks-scan".
var checkOnlyKeywords = []string{"test", "lint", "check", "coverage", "validate", "audit", "scan", "note", "changelog", "cleanup"}

// buildKeywords mark a build. They outweigh the weaker deploy words
// (release-build, assembleRelease, build-migrations), not push, publish or
// deploy: build-and-push still publishes.
var buildKeywords = []string{"build", "compile", "assemble"}

// strongDeployKeywords name the act of shipping something.
var strongDeployKeywords = []string{"deploy", "publish", "push", "upload", "rollout", "ship"}

// deployLikeName reports whether a job or stage name (lower case) says it
// deploys, given the keywords that count for the caller.
func deployLikeName(lower string, keywords []string) bool {
	// A pre-release stage checks before a release (#1052).
	lower = preReleaseReplacer.Replace(lower)
	if hasWordPrefix(lower, checkOnlyKeywords) {
		return false
	}
	if !containsAny(lower, keywords) {
		return false
	}
	return containsAny(lower, strongDeployKeywords) || !containsAny(lower, buildKeywords)
}

var preReleaseReplacer = strings.NewReplacer("pre-release", "", "pre_release", "", "prerelease", "", "pre release", "")

// hasWordPrefix reports whether a word of s (split at anything that is not a
// letter or digit) starts with one of words: "k8s-test" and "linting" match
// test and lint, "latest" doesn't.
func hasWordPrefix(s string, words []string) bool {
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) {
		for _, w := range words {
			if strings.HasPrefix(tok, w) {
				return true
			}
		}
	}
	return false
}

func containsAny(s string, words []string) bool {
	for _, w := range words {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}

// runsInheritedJob reports whether a job is one GitLab runs and whose
// inherited keys are all visible here: not a hidden template, and not
// extending a template from another file.
func runsInheritedJob(in *Inheritance, name, job *yaml.Node) bool {
	return !strings.HasPrefix(name.Value, ".") && in.ExtendsResolved(job) && !in.IncludedOverride(job)
}

// isSensitiveJob reports a job that deploys through its environment: or its
// stage. With devTierDeploys false (GL019), an environment whose
// deployment_tier is development or testing doesn't count as a deploy (#797),
// and an explicit one, or one whose action only uses the environment, decides
// whatever the stage is called (#1052); a tier guessed from the name doesn't
// outweigh the stage (pub-dev-plugin, safari-testflight publish). GL017 keeps them: such
// jobs still get the environment's variables.
func isSensitiveJob(in *Inheritance, job *yaml.Node, devTierDeploys bool) bool {
	// An environment: deploys unless its action only uses the environment;
	// then the stage still decides.
	if env := in.Key(job, "environment"); env != nil {
		if envActionStops(env) {
			return false
		}
		if t, explicit := envTier(env); !devTierDeploys && (envActionNoDeploy(env) || explicit && (t == "development" || t == "testing")) {
			return false
		}
		if !envActionNoDeploy(env) && (devTierDeploys || !in.jobEnvDevTier(job, env)) {
			return true
		}
	}
	stageNode := in.Key(job, "stage")
	if stageNode != nil && stageNode.Kind == yaml.ScalarNode &&
		deployLikeName(strings.ToLower(stageNode.Value), deployStageKeywords) {
		// A deploy/release-named stage alone over-fires on build-only jobs that
		// only produce the artifact a later job ships; require the script to
		// actually deploy or publish (#1096).
		return jobScriptDeploys(in, job)
	}
	return false
}
