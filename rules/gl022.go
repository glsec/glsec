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

type gl022 struct{}

var GL022 = &gl022{}

func (r *gl022) ID() string { return "GL022" }

// pmInstallCheck describes how to detect an unpinned package manager install.
type pmInstallCheck struct {
	manager string
	trigger prefiltered    // matches the install command
	pinned  *regexp.Regexp // if present, version is pinned → no finding
	skip    *regexp.Regexp // if present, skip the line entirely (e.g. -r file)
	// mask matches the check against a quote-masked copy of the line, so that
	// package names mentioned in prose (`echo "run npm install locally"`) are
	// not read as install commands.
	mask bool
	// run marks a launcher that fetches a package and executes it in one step,
	// so the finding says it runs rather than installs.
	run bool
}

// adhocFirstArg matches the first non-flag argument of an install command,
// i.e. an explicitly named package. The argument must be unquoted: after
// masking, a quoted argument carries no version information, so flagging it
// would report `yarn add "pkg@1.2.3"` as unpinned.
const adhocFirstArg = `\s+(?:-{1,2}[\w=@./:-]+\s+)*[^-\s"']`

// pmUpdateCheck describes explicit update-to-latest commands that are always wrong in CI.
type pmUpdateCheck struct {
	manager string
	re      prefiltered
}

var (
	pmInstallChecks = []pmInstallCheck{
		{
			manager: "pip",
			trigger: mustCompilePrefiltered(`\bpip[23]?\s+install\b`),
			pinned:  regexp.MustCompile(`==|~=|!=|>=|<=`),
			skip:    regexp.MustCompile(`\s-r\s|\s-r$|-e\s|--editable\s|\.\s*(?:$|&&|\|)|\s["']?\.{1,2}(?:/|\[|["']|\s|$)|--upgrade\b|-U\b`),
		},
		{
			manager: "npm (global)",
			trigger: mustCompilePrefiltered(`\bnpm\s+(?:install|i|add)\b.*(?:-g\b|--global\b)`),
			pinned:  regexp.MustCompile(`@\d`),
			skip:    nil,
		},
		{
			// A named package installed on top of the manifest — the dependency
			// is in no package.json and no lockfile, so the registry decides the
			// version on every run. Bare `npm install` is GL023's territory.
			manager: "npm (ad-hoc)",
			trigger: mustCompilePrefiltered(`\bnpm\s+(?:install|i|add)` + adhocFirstArg),
			pinned:  regexp.MustCompile(`@\d`),
			skip:    regexp.MustCompile(`-g\b|--global\b|\s\.{1,2}/|\sfile:|\s\.\s*(?:$|&&|\|)`),
			mask:    true,
		},
		{
			manager: "yarn (ad-hoc)",
			trigger: mustCompilePrefiltered(`\byarn\s+(?:global\s+)?add` + adhocFirstArg),
			pinned:  regexp.MustCompile(`@\d`),
			skip:    regexp.MustCompile(`\s\.{1,2}/|\sfile:|\slink:`),
			mask:    true,
		},
		{
			manager: "pnpm (ad-hoc)",
			trigger: mustCompilePrefiltered(`\bpnpm\s+add` + adhocFirstArg),
			pinned:  regexp.MustCompile(`@\d`),
			skip:    regexp.MustCompile(`\s\.{1,2}/|\sfile:|\slink:|\sworkspace:`),
			mask:    true,
		},
		{
			// npx resolves node_modules/.bin first, so a bare `npx eslint` almost
			// always runs a project devDependency. Only the forms that say the
			// package comes from the registry are flagged: an explicit -y/--yes
			// (or npm_config_yes=true), or a dist-tag on the package name.
			manager: "npx",
			trigger: mustCompilePrefiltered(`\bnpm_config_yes=true\s+npx\b|\b(?:npx|npm\s+(?:exec|x))\s+(?:-{1,2}[\w=@./:-]+\s+)*?(?:-y|--yes)\b|\bnpx\s+(?:-{1,2}[\w=@./:-]+\s+)*(?:@[\w.-]+/)?[\w.-]+@[A-Za-z]`),
			pinned:  regexp.MustCompile(`@\d`),
			mask:    true,
			run:     true,
		},
		{
			manager: "pnpm/yarn dlx",
			trigger: mustCompilePrefiltered(`\b(?:pnpm|yarn)\s+dlx` + adhocFirstArg),
			pinned:  regexp.MustCompile(`@\d`),
			skip:    regexp.MustCompile(`\s\.{1,2}/|\sfile:|\slink:`),
			mask:    true,
			run:     true,
		},
		{
			manager: "uvx / pipx run",
			trigger: mustCompilePrefiltered(`\b(?:uvx|uv\s+tool\s+run|pipx\s+run)` + adhocFirstArg),
			pinned:  regexp.MustCompile(`@\d|==\d`),
			// A local project as the package source: `uvx --from . tool`.
			skip: regexp.MustCompile(`(?:uvx|run|--from|--spec)(?:\s+|=)\.{1,2}(?:/|\s|$)`),
			mask: true,
			run:  true,
		},
		{
			manager: "bundler (ad-hoc)",
			trigger: mustCompilePrefiltered(`\bbundle\s+add` + adhocFirstArg),
			// Accepts a quoted constraint too: --version '~> 7.1'.
			pinned: regexp.MustCompile(`(?:-v|--version)\s+["']?[~^><=\s]*\d`),
			skip:   nil,
			mask:   true,
		},
		{
			manager: "apt-get",
			trigger: mustCompilePrefiltered(`\bapt(?:-get)?\s+install\b`),
			pinned:  regexp.MustCompile(`\b\S+=\d`),
			skip:    nil,
		},
		{
			manager: "apk",
			trigger: mustCompilePrefiltered(`\bapk\s+add\b`),
			pinned:  regexp.MustCompile(`\b\S+=\d`),
			skip:    nil,
		},
		{
			manager: "gem",
			trigger: mustCompilePrefiltered(`\bgem\s+install\b`),
			pinned:  regexp.MustCompile(`(?:-v|--version)\s+\d`),
			skip:    nil,
		},
		{
			manager: "cargo",
			trigger: mustCompilePrefiltered(`\bcargo\s+install\b`),
			pinned:  regexp.MustCompile(`(?:--version|--vers)\s+\d`),
			skip:    nil,
		},
		{
			manager: "composer require",
			trigger: mustCompilePrefiltered(`\bcomposer\s+require\b`),
			pinned:  regexp.MustCompile(`:\S`),
			skip:    nil,
		},
		{
			manager: "yum",
			trigger: mustCompilePrefiltered(`\byum\s+install\b`),
			pinned:  regexp.MustCompile(`\b\S+-\d`),
			skip:    nil,
		},
		{
			manager: "dnf",
			trigger: mustCompilePrefiltered(`\bdnf\s+install\b`),
			pinned:  regexp.MustCompile(`\b\S+-\d`),
			skip:    nil,
		},
		{
			manager: "zypper",
			trigger: mustCompilePrefiltered(`\bzypper\s+(?:install|in)\b`),
			pinned:  regexp.MustCompile(`\b\S+=\d`),
			skip:    nil,
		},
		{
			manager: "go",
			trigger: mustCompilePrefiltered(`\bgo\s+install\b`),
			pinned:  regexp.MustCompile(`@v?\d`),
			// Local builds (no module, or a relative/absolute path target) need no version.
			skip: regexp.MustCompile(`\bgo\s+install\s*$|\bgo\s+install\s+(?:-\S+\s+)*[./]`),
		},
	}

	// pmVarPkg matches an install whose first non-flag argument is a CI variable
	// (e.g. `apt-get install -y $PKG`). The version can't be checked statically, so
	// the line is skipped to avoid false positives.
	pmVarPkg = regexp.MustCompile(`\b(?:install|add|require|in|npx|npm\s+(?:exec|x)|dlx|uvx|uv\s+tool\s+run|pipx\s+run)\s+(?:-\S+\s+)*["']?\$\{?[A-Za-z_]`)

	// varPinnedRe matches a version given through a variable: pkg@$V,
	// pkg==$V, pkg=$V, -v $V, --version=${V}. The value is unknown statically,
	// like a package named by a variable (pmVarPkg), so it isn't flagged.
	varPinnedRe = regexp.MustCompile(`(?:@|==|[^\s=-]=|(?:-v|--version|--vers)[\s=]+)["']?\$\{?[A-Za-z_]`)

	// localPackageRe matches a package file or directory on disk, such as
	// ./dist/tool.deb or /tmp/pkg.whl (a relative path or a package file): a local build, not a registry package.
	localPackageRe = regexp.MustCompile(`(?:^|\s)["']?\.{1,2}/\S*|\S+\.(?:deb|rpm|whl|apk)\b`)

	pmUpdateChecks = []pmUpdateCheck{
		{"npm", mustCompilePrefiltered(`\bnpm\s+update\b`)},
		{"yarn", mustCompilePrefiltered(`\byarn\s+upgrade\b`)},
		{"pnpm", mustCompilePrefiltered(`\bpnpm\s+update\b`)},
		{"composer", mustCompilePrefiltered(`\bcomposer\s+update\b`)},
		{"bundler", mustCompilePrefiltered(`\bbundle\s+update\b`)},
		{"gem", mustCompilePrefiltered(`\bgem\s+update\b`)},
		{"cargo", mustCompilePrefiltered(`\bcargo\s+update\b`)},
		{"pip (--upgrade)", mustCompilePrefiltered(`\bpip[23]?\s+install\b.*(?:--upgrade\b|-U\b)`)},
	}
)

func (r *gl022) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	// A script line shared by several jobs through an anchor is checked
	// once; the other jobs' findings would be merged by finding.Dedupe.
	seen := map[*yaml.Node]bool{}
	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		lines := CollectJobScriptLines(job)
		for _, l := range lines {
			if seen[l] {
				continue
			}
			seen[l] = true
			if f := checkPMLine(l.Value, file, l.Line, l.Column); f != nil {
				f.Job = name.Value
				findings = append(findings, *f)
			}
		}
	})

	return findings
}

func checkPMLine(line, file string, lineNum, col int) *finding.Finding {
	// Explicit update commands — always wrong in CI.
	for _, uc := range pmUpdateChecks {
		if uc.re.MatchString(line) {
			f := finding.Finding{
				RuleID:   "GL022",
				Severity: finding.Warn,
				Message:  fmt.Sprintf("%s update command used in CI — always pulls latest, making the pipeline non-reproducible", uc.manager),
				File:     file,
				Line:     lineNum,
				Col:      col,
			}
			return &f
		}
	}

	// Install without version pin.
	for _, ic := range pmInstallChecks {
		// Only the trigger runs against the masked copy: masking exists to stop
		// prose inside a quoted string from reading as a command. The pin check
		// stays on the raw line so that a quoted version constraint
		// (`bundle add rails --version '~> 7.1'`) still counts as pinned.
		probe := line
		if ic.mask {
			probe = maskShellQuotes(line)
		}
		if !ic.trigger.MatchString(probe) {
			continue
		}
		if ic.skip != nil && ic.skip.MatchString(line) {
			continue
		}
		if pmVarPkg.MatchString(line) {
			continue
		}
		if ic.pinned != nil && ic.pinned.MatchString(line) {
			continue
		}
		// Only the rest of the install command can pin or name a package: not
		// a VAR=$X prefix in front of it, and not other commands in a block.
		args := line[ic.trigger.FindStringIndex(probe)[1]:]
		if end := strings.IndexAny(args, "\n;|&"); end >= 0 {
			args = args[:end]
		}
		if varPinnedRe.MatchString(args) || localPackageRe.MatchString(args) {
			continue
		}
		manager := ic.manager
		if manager == "apt-get" && strings.HasPrefix(ic.trigger.FindString(probe), "apt ") {
			manager = "apt" // name the command as written (#1005)
		}
		msg := fmt.Sprintf("%s install without version pin — use an exact version to make the pipeline reproducible", manager)
		if ic.run {
			msg = fmt.Sprintf("%s fetches and runs a package without version pin — use an exact version to make the pipeline reproducible", manager)
		}
		f := finding.Finding{
			RuleID:   "GL022",
			Severity: finding.Warn,
			Message:  msg,
			File:     file,
			Line:     lineNum,
			Col:      col,
		}
		return &f
	}

	return nil
}
