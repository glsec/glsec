// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

type gl090 struct{}

var GL090 = &gl090{}

func (r *gl090) ID() string { return "GL090" }

// lifecycleEcosystem describes, for one package ecosystem, the install
// commands that run code from dependencies and the commands that publish a
// package (#1132, #1139).
type lifecycleEcosystem struct {
	// installs reports a dependency install that runs dependency code, unless
	// a setting or an argument switches that off.
	installs func(words []string) bool
	// publishes reports a command that publishes a package.
	publishes func(words []string) bool
	// offRe matches a setting that switches dependency code off: in front of
	// an install for that install, as its own command for later installs.
	// nil when the ecosystem has none.
	offRe *regexp.Regexp
	// onRe matches a setting that switches it back on, such as
	// ignore-scripts false or unset of the variable (#1301). nil when the
	// ecosystem has none.
	onRe *regexp.Regexp
	// offArg reports an install argument that switches it off for that
	// install.
	offArg func(words []string) bool
	// offVars reports variables reaching the job that switch it
	// off.
	offVars func(vars jobVariables) bool
	// risk and fix complete the message.
	risk, fix string
}

// npmInstallCmds are the npm subcommands that install dependencies.
var npmInstallCmds = map[string]bool{
	"ci": true, "clean-install": true, "ic": true, "install-clean": true,
	"install": true, "i": true, "in": true, "add": true,
	"install-test": true, "it": true, "install-ci-test": true, "cit": true,
}

// lifecycleEcosystems lists npm, Python and RubyGems.
//
// npm: pnpm 10 and bun don't run the lifecycle scripts of dependencies by
// default, so their installs are not listed; their publish commands are,
// since an npm or yarn install in the same job still runs them.
//
// Python: a wheel installs without running package code, an sdist runs its
// setup.py or build backend. Only installs of the project's dependency tree
// count; a named tool install (pip install twine build) gets wheels.
//
// RubyGems: bundle install runs the extconf.rb of every gem with a native
// extension, and nothing switches that off.
var lifecycleEcosystems = [...]lifecycleEcosystem{
	{
		installs: func(w []string) bool {
			// A global install (npm install -g npm@11) adds a named tool,
			// not the project's dependency tree.
			if slices.Contains(w, "-g") || slices.Contains(w, "--global") || slices.Contains(w, "--location=global") {
				return false
			}
			switch commandName(w) {
			case "npm":
				return npmInstallCmds[subcommand(w)]
			case "yarn":
				switch subcommand(w) {
				case "":
					return !printsInfo(w)
				case "install", "add":
					return true
				}
			}
			return false
		},
		publishes: func(w []string) bool {
			switch commandName(w) {
			case "npm", "pnpm":
				return subcommand(w) == "publish"
			case "yarn":
				if subcommand(w) == "publish" {
					return true
				}
				// yarn npm publish, yarn workspaces foreach … npm publish
				for i := 1; i+1 < len(w); i++ {
					if w[i] == "npm" && w[i+1] == "publish" {
						return true
					}
				}
			}
			return false
		},
		offRe:   scriptsOffRe,
		onRe:    scriptsOnRe,
		offArg:  func(w []string) bool { return scriptsOffArgRe.MatchString(strings.Join(w, " ")) },
		offVars: scriptsDisabledByVariables,
		risk:    "installs dependencies with lifecycle scripts enabled",
		fix:     `any dependency's install script runs with the publish token; add --ignore-scripts or set NPM_CONFIG_IGNORE_SCRIPTS: "true", or build in one job and publish the artifact from a job that installs nothing (suppress if .npmrc sets ignore-scripts=true)`,
	},
	{
		installs:  pythonInstallsDeps,
		publishes: pythonPublishes,
		offRe:     pythonBuildOffRe,
		onRe:      pythonBuildOnRe,
		offArg:    pythonBinaryOnlyArg,
		offVars:   pythonBuildDisabledByVariables,
		risk:      "installs the project's dependencies, building any without a wheel from source",
		fix:       `a dependency's setup.py or build backend runs with the publish token; add --only-binary :all: (uv: --no-build) or set PIP_ONLY_BINARY: ":all:", or build in one job and upload dist/ from a job that installs nothing`,
	},
	{
		installs: func(w []string) bool {
			switch commandName(w) {
			case "bundle", "bundler":
				switch subcommand(w) {
				case "":
					return !printsInfo(w)
				case "install":
					return true
				}
			}
			return false
		},
		publishes: rubyPublishes,
		offArg:    func([]string) bool { return false },
		offVars:   func(jobVariables) bool { return false },
		risk:      "installs gems, building their native extensions",
		fix:       "a gem's extconf.rb runs with the publish token; build the gem in one job and run gem push from a job that installs nothing",
	},
}

var (
	// scriptsOffRe matches a setting that switches dependency lifecycle
	// scripts off for later installs: npm config set ignore-scripts true, an
	// .npmrc line written by echo, the npm and Yarn 2+ environment variables,
	// and yarn config set enableScripts false.
	scriptsOffRe = regexp.MustCompile(`(?i)ignore[-_]scripts(?:\s*=\s*|\s+)["']?true\b|yarn_enable_scripts=["']?(?:false|0)\b|enableScripts(?:\s*:\s*|\s+)["']?false\b`)
	// scriptsOffArgRe matches an install argument that switches them off for
	// that install: --ignore-scripts, and Yarn 2+'s --mode=skip-build.
	scriptsOffArgRe = regexp.MustCompile(`(?:^|\s)(?:--ignore-scripts(?:=true)?|--mode[= ]skip-build)(?:\s|$)`)
	// pythonBuildOffRe matches a setting that stops builds from source:
	// PIP_ONLY_BINARY=:all:, UV_NO_BUILD=1, POETRY_INSTALLER_ONLY_BINARY
	// (Poetry 2), pip config set and poetry config, and an only-binary line
	// written to pip.conf.
	pythonBuildOffRe = regexp.MustCompile(`\bPIP_ONLY_BINARY=["']?:all:|\bUV_NO_BUILD=["']?(?:1|[Tt]rue|yes|on)\b|\bPOETRY_INSTALLER_ONLY_BINARY=["']?(?::all:|[Tt]rue)|\bconfig\s+set\s+(?:global|install)\.only-binary\s+["']?:all:|\bconfig\s+installer\.only-binary\s+["']?(?::all:|[Tt]rue)|only-binary\s*=\s*:all:`)
	// scriptsOnRe and pythonBuildOnRe match the settings that undo those:
	// the value set back, a config delete, or unset of the variable.
	scriptsOnRe     = regexp.MustCompile(`(?i)ignore[-_]scripts(?:\s*=\s*|\s+)["']?false\b|\bconfig\s+(?:delete|rm|unset)\s+ignore[-_]scripts\b|\bunset\b.*\b(?:npm_config_ignore_scripts|yarn_enable_scripts)\b|yarn_enable_scripts=["']?(?:true|1)\b|enableScripts(?:\s*:\s*|\s+)["']?true\b`)
	pythonBuildOnRe = regexp.MustCompile(`\bunset\b.*\b(?:PIP_ONLY_BINARY|UV_NO_BUILD|POETRY_INSTALLER_ONLY_BINARY)\b|\bPIP_ONLY_BINARY=["']?:none:|\bUV_NO_BUILD=["']?(?:0|(?i:false)|no|off)\b|\bPOETRY_INSTALLER_ONLY_BINARY=["']?(?::none:|(?i:false))|\bconfig\s+unset\s+(?:global|install)\.only-binary\b`)
	pipNameRe       = regexp.MustCompile(`^pip[0-9.]*$`)
	pythonNameRe    = regexp.MustCompile(`^(?:python[0-9.]*|py)$`)
)

// Check reports a job that publishes a package and also installs
// dependencies in a way that runs their code: any dependency's install
// script, setup.py or native extension build then runs with the publish
// token in the environment, the vector of the 2025 npm worms (#1132).
func (r *gl090) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	in := NewInheritance(doc)
	pipelineVars := pipelineVariablesOf(doc)
	type pos struct {
		item *yaml.Node
		line int
		text string
	}
	parser.EachJob(doc, func(name, job *yaml.Node) {
		if strings.HasPrefix(name.Value, ".") {
			return
		}
		var items []*yaml.Node
		publishes := false
		for _, key := range []string{"before_script", "script"} {
			block := in.Key(job, key)
			if !isScriptList(block) {
				continue
			}
			for _, item := range block.Content {
				if item.Kind == yaml.ScalarNode && mentionsPackageTool(item.Value) {
					items = append(items, item)
					publishes = publishes || mentionsPublish(item.Value)
				}
			}
		}
		// Splitting every line into commands is costly; most jobs publish
		// nothing.
		if !publishes {
			return
		}
		var install, publish [len(lifecycleEcosystems)]*pos
		// off is the effective setting of the job's shell; a sh -c child has
		// its own, keyed by the command that starts it, which ends with it.
		var off [len(lifecycleEcosystems)]bool
		var childOff [len(lifecycleEcosystems)]map[string]bool
		for _, item := range items {
			for _, cmd := range shellCommands(item.Value) {
				words := commandWords(cmd.text)
				env := commandEnvironment(cmd.text)
				for i, eco := range lifecycleEcosystems {
					switch {
					case eco.installs(words):
						offNow := off[i] || childOff[i][cmd.parent]
						if eco.onRe != nil && eco.onRe.MatchString(strings.Join(env.local, " ")) {
							offNow = false
						}
						offHere := eco.offRe != nil && eco.offRe.MatchString(cmd.text)
						if install[i] == nil && !offNow && !offHere && !eco.offArg(words) {
							install[i] = &pos{item, cmd.line, cmd.text}
						}
					case eco.publishes(words):
						if publish[i] == nil {
							publish[i] = &pos{item, cmd.line, cmd.text}
						}
					default:
						set, value := eco.setting(cmd, words, env)
						if !set {
							continue
						}
						if cmd.parent == "" {
							off[i] = value
							continue
						}
						if childOff[i] == nil {
							childOff[i] = map[string]bool{}
						}
						childOff[i][cmd.parent] = value
					}
				}
			}
		}
		var vars jobVariables
		varsDone := false
		for i, eco := range lifecycleEcosystems {
			if install[i] == nil || publish[i] == nil {
				continue
			}
			if !varsDone {
				vars, varsDone = variablesOf(in, job, pipelineVars), true
			}
			if eco.offVars(vars) {
				continue
			}
			f := finding.Finding{
				RuleID:   "GL090",
				Severity: finding.Warn,
				Job:      name.Value,
				Message:  fmt.Sprintf("job %q publishes a package (%q) and %s (%q) — %s", name.Value, truncate(publish[i].text, 40), eco.risk, truncate(install[i].text, 40), eco.fix),
				File:     file,
				Line:     parser.ScalarContentLine(install[i].item, install[i].line),
			}
			if install[i].line == 0 {
				f.Col = install[i].item.Column
			}
			findings = append(findings, f)
		}
	})
	return findings
}

// setting reports whether a command that neither installs nor publishes
// changes the setting for later commands, and to what (#1301). An assignment
// in front of a program applies to that program only; text that echo or
// printf only prints is not a setting, while the same text written to a file
// such as .npmrc is.
func (eco lifecycleEcosystem) setting(cmd shellCommand, words []string, env commandEnv) (set, off bool) {
	if eco.offRe == nil {
		return false, false
	}
	var text string
	switch {
	case len(words) == 0:
		text = strings.Join(env.persistent, " ")
	case printsOnly(cmd, words):
		return false, false
	case mayRunShellC(cmd.text):
		// sh -c "…": its commands come separately, in their own scope.
		if _, ok := shellCText(cmd.text); ok {
			return false, false
		}
		text = strings.Join(words, " ")
	default:
		text = strings.Join(words, " ")
	}
	switch {
	case eco.offRe.MatchString(text):
		return true, true
	case eco.onRe != nil && eco.onRe.MatchString(text):
		return true, false
	}
	return false, false
}

// mentionsPackageTool reports whether a script item can hold an install, a
// publish or a setting that switches dependency code off.
func mentionsPackageTool(s string) bool {
	for _, t := range packageToolHints {
		if strings.Contains(s, t) {
			return true
		}
	}
	return false
}

var packageToolHints = []string{
	"npm", "yarn", "NPM_", "YARN_",
	"pip", "poetry", "uv", "pdm", "twine", "flit", "hatch", "PIP_", "UV_", "POETRY_", "only-binary",
	"bundle", "gem", "rake",
}

// mentionsPublish reports whether a script item can hold a publish command.
func mentionsPublish(s string) bool {
	return strings.Contains(s, "publish") || strings.Contains(s, "twine") ||
		strings.Contains(s, "gem push") || strings.Contains(s, "rake")
}

// pythonTool returns the words from the Python tool on: python -m pip … is
// pip …, and uv run, poetry run, pipenv run, pdm run, hatch run, pipx run
// and uvx run the tool that follows.
func pythonTool(w []string) []string {
	for len(w) > 1 {
		name := commandName(w)
		switch {
		case pythonNameRe.MatchString(name) && len(w) > 2 && w[1] == "-m":
			w = w[2:]
		case (name == "uv" || name == "poetry" || name == "pipenv" || name == "pdm" || name == "hatch" || name == "pipx") && len(w) > 2 && w[1] == "run":
			w = w[2:]
		case name == "uvx":
			w = w[1:]
		default:
			return w
		}
	}
	return w
}

// pythonPublishes reports twine upload, poetry/uv/flit/hatch/pdm publish. A
// dry run uploads nothing.
func pythonPublishes(w []string) bool {
	w = pythonTool(w)
	if len(w) == 0 || slices.Contains(w, "--dry-run") {
		return false
	}
	switch commandName(w) {
	case "twine":
		return subcommand(w) == "upload"
	case "poetry", "uv", "flit", "hatch", "pdm":
		return subcommand(w) == "publish"
	}
	return false
}

// pythonInstallsDeps reports an install of the project's dependency tree:
// pip install -r …, pip install . / -e ., uv pip install and uv pip sync,
// poetry install, uv sync, pipenv install/sync, pdm install/sync.
func pythonInstallsDeps(w []string) bool {
	w = pythonTool(w)
	if len(w) == 0 {
		return false
	}
	name := commandName(w)
	if name == "uv" && subcommand(w) == "pip" {
		w = w[slices.Index(w, "pip"):]
		if subcommand(w) == "sync" {
			return true
		}
		name = "pip"
	}
	switch {
	case pipNameRe.MatchString(name):
		if subcommand(w) != "install" {
			return false
		}
		return pipInstallsProject(w[slices.Index(w, "install")+1:])
	case name == "poetry":
		return subcommand(w) == "install"
	case name == "uv":
		return subcommand(w) == "sync"
	case name == "pipenv", name == "pdm":
		switch subcommand(w) {
		case "install", "sync":
			return true
		}
	}
	return false
}

// pipValueOptions are pip install options whose value is the next word, so
// a value such as -t ./lib is not read as a local project.
var pipValueOptions = map[string]bool{
	"-c": true, "--constraint": true, "-i": true, "--index-url": true,
	"--extra-index-url": true, "-f": true, "--find-links": true,
	"-t": true, "--target": true, "--prefix": true, "--root": true,
	"--src": true, "--only-binary": true, "--no-binary": true,
	"--platform": true, "--python-version": true, "--implementation": true,
	"--abi": true, "--trusted-host": true, "--upgrade-strategy": true,
	"--cache-dir": true, "--log": true, "--proxy": true, "--timeout": true,
	"--retries": true, "--cert": true, "--client-cert": true, "-C": true,
	"--config-settings": true, "--python": true, "-p": true,
}

// pipInstallsProject reports pip install arguments that install a
// requirements file or a local project with its dependencies. A local
// project alone (--no-deps) is the job's own code.
func pipInstallsProject(args []string) bool {
	local, noDeps := false, false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-r" || a == "--requirement" || a == "--requirements" ||
			strings.HasPrefix(a, "--requirement=") || strings.HasPrefix(a, "--requirements=") ||
			len(a) > 2 && a[0] == '-' && a[1] != '-' && strings.ContainsRune(a[1:], 'r'):
			return true
		case a == "--no-deps":
			noDeps = true
		case a == "-e" || a == "--editable" || strings.HasPrefix(a, "--editable="):
			local = true
		case pipValueOptions[a]:
			i++
		case strings.HasPrefix(a, "-"):
		case a == "." || strings.HasPrefix(a, ".[") || strings.HasPrefix(a, "./") || strings.HasPrefix(a, "../"):
			if !strings.HasSuffix(a, ".whl") {
				local = true
			}
		}
	}
	return local && !noDeps
}

// pythonBinaryOnlyArg reports an install argument that stops builds from
// source: --only-binary :all: for pip and uv pip, --no-build for uv.
func pythonBinaryOnlyArg(w []string) bool {
	for i, a := range w {
		switch {
		case a == "--no-build", a == "--only-binary=:all:":
			return true
		case a == "--only-binary" && i+1 < len(w) && w[i+1] == ":all:":
			return true
		}
	}
	return false
}

// pythonBuildDisabledByVariables reports variables that stop builds from
// source for pip, uv or Poetry on every path through the job.
func pythonBuildDisabledByVariables(vars jobVariables) bool {
	return vars.always("PIP_ONLY_BINARY", func(v string) bool { return v == ":all:" }) ||
		vars.always("UV_NO_BUILD", func(v string) bool {
			switch strings.ToLower(v) {
			case "1", "true", "yes", "on":
				return true
			}
			return false
		}) ||
		vars.always("POETRY_INSTALLER_ONLY_BINARY", func(v string) bool { return v == ":all:" || isTrueValue(v) })
}

// rubyPublishes reports gem push and rake release, the Bundler gem task
// that runs it, also as bundle exec rake release.
func rubyPublishes(w []string) bool {
	if (commandName(w) == "bundle" || commandName(w) == "bundler") && len(w) > 2 && w[1] == "exec" {
		w = w[2:]
	}
	switch commandName(w) {
	case "gem":
		return subcommand(w) == "push"
	case "rake":
		for _, a := range w[1:] {
			if a == "release" || strings.HasPrefix(a, "release:") || strings.HasPrefix(a, "release[") {
				return true
			}
		}
	}
	return false
}

// subcommand returns the first word after the program that is not an
// option, or "" when there is none (a bare yarn).
// printsInfo reports a command that only prints its version or help, such as
// yarn --version: with no subcommand it would otherwise read as a bare yarn,
// which installs (#1275).
func printsInfo(words []string) bool {
	for _, w := range words[1:] {
		switch w {
		case "--version", "-v", "--help", "-h":
			return true
		}
	}
	return false
}

func subcommand(words []string) string {
	for _, w := range words[1:] {
		if !strings.HasPrefix(w, "-") {
			return w
		}
	}
	return ""
}

// scriptsDisabledByVariables reports variables that switch dependency
// lifecycle scripts off for npm or Yarn 2+ on every path through the job.
func scriptsDisabledByVariables(vars jobVariables) bool {
	return vars.always("NPM_CONFIG_IGNORE_SCRIPTS", isTrueValue) ||
		vars.always("npm_config_ignore_scripts", isTrueValue) ||
		vars.always("YARN_ENABLE_SCRIPTS", func(v string) bool { return strings.EqualFold(v, "false") || v == "0" })
}
