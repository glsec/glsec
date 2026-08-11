package rules

import (
	"fmt"
	"regexp"

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
	trigger *regexp.Regexp // matches the install command
	pinned  *regexp.Regexp // if present, version is pinned → no finding
	skip    *regexp.Regexp // if present, skip the line entirely (e.g. -r file)
	// mask matches the check against a quote-masked copy of the line, so that
	// package names mentioned in prose (`echo "run npm install locally"`) are
	// not read as install commands.
	mask bool
}

// adhocFirstArg matches the first non-flag argument of an install command,
// i.e. an explicitly named package. The argument must be unquoted: after
// masking, a quoted argument carries no version information, so flagging it
// would report `yarn add "pkg@1.2.3"` as unpinned.
const adhocFirstArg = `\s+(?:-{1,2}[\w=@./:-]+\s+)*[^-\s"']`

// pmUpdateCheck describes explicit update-to-latest commands that are always wrong in CI.
type pmUpdateCheck struct {
	manager string
	re      *regexp.Regexp
}

var (
	pmInstallChecks = []pmInstallCheck{
		{
			manager: "pip",
			trigger: regexp.MustCompile(`\bpip[23]?\s+install\b`),
			pinned:  regexp.MustCompile(`==|~=|!=|>=|<=`),
			skip:    regexp.MustCompile(`\s-r\s|\s-r$|-e\s|\.\s*(?:$|&&|\|)|--upgrade\b|-U\b`),
		},
		{
			manager: "npm (global)",
			trigger: regexp.MustCompile(`\bnpm\s+(?:install|i|add)\b.*(?:-g\b|--global\b)`),
			pinned:  regexp.MustCompile(`@\d`),
			skip:    nil,
		},
		{
			// A named package installed on top of the manifest — the dependency
			// is in no package.json and no lockfile, so the registry decides the
			// version on every run. Bare `npm install` is GL023's territory.
			manager: "npm (ad-hoc)",
			trigger: regexp.MustCompile(`\bnpm\s+(?:install|i|add)` + adhocFirstArg),
			pinned:  regexp.MustCompile(`@\d`),
			skip:    regexp.MustCompile(`-g\b|--global\b|\s\.{1,2}/|\sfile:|\s\.\s*(?:$|&&|\|)`),
			mask:    true,
		},
		{
			manager: "yarn (ad-hoc)",
			trigger: regexp.MustCompile(`\byarn\s+add` + adhocFirstArg),
			pinned:  regexp.MustCompile(`@\d`),
			skip:    regexp.MustCompile(`\s\.{1,2}/|\sfile:|\slink:`),
			mask:    true,
		},
		{
			manager: "pnpm (ad-hoc)",
			trigger: regexp.MustCompile(`\bpnpm\s+add` + adhocFirstArg),
			pinned:  regexp.MustCompile(`@\d`),
			skip:    regexp.MustCompile(`\s\.{1,2}/|\sfile:|\slink:|\sworkspace:`),
			mask:    true,
		},
		{
			manager: "bundler (ad-hoc)",
			trigger: regexp.MustCompile(`\bbundle\s+add` + adhocFirstArg),
			// Accepts a quoted constraint too: --version '~> 7.1'.
			pinned: regexp.MustCompile(`(?:-v|--version)\s+["']?[~^><=\s]*\d`),
			skip:   nil,
			mask:   true,
		},
		{
			manager: "apt-get",
			trigger: regexp.MustCompile(`\bapt(?:-get)?\s+install\b`),
			pinned:  regexp.MustCompile(`\b\S+=\d`),
			skip:    nil,
		},
		{
			manager: "apk",
			trigger: regexp.MustCompile(`\bapk\s+add\b`),
			pinned:  regexp.MustCompile(`\b\S+=\d`),
			skip:    nil,
		},
		{
			manager: "gem",
			trigger: regexp.MustCompile(`\bgem\s+install\b`),
			pinned:  regexp.MustCompile(`(?:-v|--version)\s+\d`),
			skip:    nil,
		},
		{
			manager: "cargo",
			trigger: regexp.MustCompile(`\bcargo\s+install\b`),
			pinned:  regexp.MustCompile(`(?:--version|--vers)\s+\d`),
			skip:    nil,
		},
		{
			manager: "composer require",
			trigger: regexp.MustCompile(`\bcomposer\s+require\b`),
			pinned:  regexp.MustCompile(`:\S`),
			skip:    nil,
		},
		{
			manager: "yum",
			trigger: regexp.MustCompile(`\byum\s+install\b`),
			pinned:  regexp.MustCompile(`\b\S+-\d`),
			skip:    nil,
		},
		{
			manager: "dnf",
			trigger: regexp.MustCompile(`\bdnf\s+install\b`),
			pinned:  regexp.MustCompile(`\b\S+-\d`),
			skip:    nil,
		},
		{
			manager: "zypper",
			trigger: regexp.MustCompile(`\bzypper\s+(?:install|in)\b`),
			pinned:  regexp.MustCompile(`\b\S+=\d`),
			skip:    nil,
		},
		{
			manager: "go",
			trigger: regexp.MustCompile(`\bgo\s+install\b`),
			pinned:  regexp.MustCompile(`@v?\d`),
			// Local builds (no module, or a relative/absolute path target) need no version.
			skip: regexp.MustCompile(`\bgo\s+install\s*$|\bgo\s+install\s+(?:-\S+\s+)*[./]`),
		},
	}

	// pmVarPkg matches an install whose first non-flag argument is a CI variable
	// (e.g. `apt-get install -y $PKG`). The version can't be checked statically, so
	// the line is skipped to avoid false positives.
	pmVarPkg = regexp.MustCompile(`\b(?:install|add|require|in)\s+(?:-\S+\s+)*["']?\$\{?[A-Za-z_]`)

	pmUpdateChecks = []pmUpdateCheck{
		{"npm", regexp.MustCompile(`\bnpm\s+update\b`)},
		{"yarn", regexp.MustCompile(`\byarn\s+upgrade\b`)},
		{"pnpm", regexp.MustCompile(`\bpnpm\s+update\b`)},
		{"composer", regexp.MustCompile(`\bcomposer\s+update\b`)},
		{"bundler", regexp.MustCompile(`\bbundle\s+update\b`)},
		{"gem", regexp.MustCompile(`\bgem\s+update\b`)},
		{"cargo", regexp.MustCompile(`\bcargo\s+update\b`)},
		{"pip (--upgrade)", regexp.MustCompile(`\bpip[23]?\s+install\b.*(?:--upgrade\b|-U\b)`)},
	}
)

func (r *gl022) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding

	parser.EachJob(doc, func(name *yaml.Node, job *yaml.Node) {
		lines := CollectJobScriptLines(job)
		for _, l := range lines {
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
		f := finding.Finding{
			RuleID:   "GL022",
			Severity: finding.Warn,
			Message:  fmt.Sprintf("%s install without version pin — use an exact version to make the pipeline reproducible", ic.manager),
			File:     file,
			Line:     lineNum,
			Col:      col,
		}
		return &f
	}

	return nil
}
