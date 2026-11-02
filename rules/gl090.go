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
// commands that run the lifecycle scripts of dependencies and the commands
// that publish a package. Another ecosystem (pip + twine, gem + gem push) is
// one more entry (#1132).
type lifecycleEcosystem struct {
	// installs reports a dependency install that runs lifecycle scripts,
	// unless an argument switches them off.
	installs func(words []string) bool
	// publishes reports a command that publishes a package.
	publishes func(words []string) bool
}

// npmInstallCmds are the npm subcommands that install dependencies.
var npmInstallCmds = map[string]bool{
	"ci": true, "clean-install": true, "ic": true, "install-clean": true,
	"install": true, "i": true, "in": true, "add": true,
	"install-test": true, "it": true, "install-ci-test": true, "cit": true,
}

// lifecycleEcosystems lists the npm ecosystem only. pnpm 10 and bun don't run
// the lifecycle scripts of dependencies by default, so their installs are not
// listed; their publish commands are, since an npm or yarn install in the
// same job still runs them.
var lifecycleEcosystems = []lifecycleEcosystem{
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
				case "", "install", "add":
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
)

// Check reports a job that publishes a package and also installs
// dependencies with their lifecycle scripts enabled: any dependency's
// preinstall/install/postinstall then runs with the publish token in the
// environment, the vector of the 2025 npm worms (#1132).
func (r *gl090) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	in := NewInheritance(doc)
	pipelineVars := pipelineVariableBlocks(doc)
	parser.EachJob(doc, func(name, job *yaml.Node) {
		if strings.HasPrefix(name.Value, ".") {
			return
		}
		type pos struct {
			item *yaml.Node
			line int
			text string
		}
		var install, publish *pos
		scriptsOff := false
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
					publishes = publishes || strings.Contains(item.Value, "publish")
				}
			}
		}
		// Splitting every line into commands is costly; most jobs publish
		// nothing.
		if !publishes {
			return
		}
		for _, item := range items {
			for _, cmd := range shellCommands(item.Value) {
				words := withoutSudo(commandWords(cmd.text))
				installs := false
				for _, eco := range lifecycleEcosystems {
					switch {
					case eco.installs(words):
						installs = true
						if install == nil && !scriptsOff && !scriptsOffRe.MatchString(cmd.text) && !scriptsOffArgRe.MatchString(strings.Join(words, " ")) {
							install = &pos{item, cmd.line, cmd.text}
						}
					case eco.publishes(words):
						if publish == nil {
							publish = &pos{item, cmd.line, cmd.text}
						}
					}
				}
				// An assignment in front of an install applies to that
				// install only; export or npm config set to the rest.
				if !installs && scriptsOffRe.MatchString(cmd.text) {
					scriptsOff = true
				}
			}
		}
		if install == nil || publish == nil || scriptsDisabledByVariables(jobVariableBlocks(in, job, pipelineVars)) {
			return
		}
		f := finding.Finding{
			RuleID:   "GL090",
			Severity: finding.Warn,
			Job:      name.Value,
			Message:  fmt.Sprintf("job %q publishes a package (%q) and installs dependencies with lifecycle scripts enabled (%q) — any dependency's install script runs with the publish token; add --ignore-scripts or set NPM_CONFIG_IGNORE_SCRIPTS: \"true\", or build in one job and publish the artifact from a job that installs nothing (suppress if .npmrc sets ignore-scripts=true)", name.Value, truncate(publish.text, 40), truncate(install.text, 40)),
			File:     file,
			Line:     parser.ScalarContentLine(install.item, install.line),
		}
		if install.line == 0 {
			f.Col = install.item.Column
		}
		findings = append(findings, f)
	})
	return findings
}

// mentionsPackageTool reports whether a script item can hold an install, a
// publish or a setting that switches lifecycle scripts off.
func mentionsPackageTool(s string) bool {
	return strings.Contains(s, "npm") || strings.Contains(s, "yarn") ||
		strings.Contains(s, "NPM_") || strings.Contains(s, "YARN_")
}

// subcommand returns the first word after the program that is not an
// option, or "" when there is none (a bare yarn).
func subcommand(words []string) string {
	for _, w := range words[1:] {
		if !strings.HasPrefix(w, "-") {
			return w
		}
	}
	return ""
}

// scriptsDisabledByVariables reports a variables: block reaching the job that
// switches dependency lifecycle scripts off for npm or Yarn 2+.
func scriptsDisabledByVariables(vars []*yaml.Node) bool {
	for _, name := range []string{"NPM_CONFIG_IGNORE_SCRIPTS", "npm_config_ignore_scripts"} {
		if varIsTrue(vars, name) {
			return true
		}
	}
	for _, b := range vars {
		for _, v := range varValues(b, "YARN_ENABLE_SCRIPTS") {
			if strings.EqualFold(v, "false") || v == "0" {
				return true
			}
		}
	}
	return false
}
