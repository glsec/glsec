package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/glsec/glsec/internal/config"
	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/output"
	"github.com/glsec/glsec/internal/parser"
	"github.com/glsec/glsec/internal/suppress"
	"github.com/glsec/glsec/internal/validate"
	gitlabver "github.com/glsec/glsec/internal/version"
	"github.com/glsec/glsec/rules"
)

// Set via ldflags at build time by GoReleaser.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	formatFlag := flag.String("format", "text", "output format: text, json, sarif")
	configFlag := flag.String("config", config.DefaultFile, "path to .glsec.yml config file")
	versionFlag := flag.Bool("version", false, "print version and exit")
	gitlabVersionFlag := flag.String("gitlab-version", "", "target GitLab version, e.g. 16.0 (skips rules not available in that version)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: glsec [--format text|json|sarif] [--config .glsec.yml] [--gitlab-version 16.0] [file]")
		fmt.Fprintln(os.Stderr, "       If no file is given, glsec looks for .gitlab-ci.yml in the current directory.")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *versionFlag {
		fmt.Printf("glsec %s (commit %s, built %s)\n", version, commit, date)
		return
	}

	if flag.NArg() > 1 {
		flag.Usage()
		os.Exit(2)
	}

	format, ok := output.ParseFormat(*formatFlag)
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown format %q — use text, json, or sarif\n", *formatFlag)
		os.Exit(2)
	}

	cfg, err := config.Load(*configFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	// --gitlab-version flag overrides the config file value.
	gitlabVersionStr := cfg.GitLabVersion
	if *gitlabVersionFlag != "" {
		gitlabVersionStr = *gitlabVersionFlag
	}
	gitlabVersion, err := gitlabver.Parse(gitlabVersionStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: --gitlab-version: %v\n", err)
		os.Exit(2)
	}
	if !gitlabVersion.IsZero() && !gitlabVersion.AtLeast(gitlabver.Minimum) {
		fmt.Fprintf(os.Stderr, "warning: gitlab-version %s is below the minimum supported version %s\n", gitlabVersion, gitlabver.Minimum)
	}

	file := flag.Arg(0)
	if file == "" {
		const defaultCI = ".gitlab-ci.yml"
		if _, statErr := os.Stat(defaultCI); statErr != nil {
			fmt.Fprintf(os.Stderr, "error: no .gitlab-ci.yml found in current directory — pass a file path explicitly\n")
			os.Exit(2)
		}
		file = defaultCI
	}

	doc, err := parser.ParseFile(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	warns, valErr := validate.File(file, doc)
	for _, w := range warns {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}
	if valErr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", valErr)
		os.Exit(2)
	}

	suppressMap := suppress.Build(doc.Root)

	var findings []finding.Finding
	for _, rule := range rules.All() {
		if !cfg.RuleEnabled(rule.ID()) {
			continue
		}
		if !rules.EnabledFor(rule.ID(), gitlabVersion) {
			continue
		}
		for _, f := range rule.Check(doc.Root, file) {
			if suppressMap.IsSuppressed(f.Line, f.RuleID) {
				continue
			}
			f = cfg.ApplySeverity(f)
			if cfg.AboveMinSeverity(f) {
				findings = append(findings, f)
			}
		}
	}

	if err := output.Write(os.Stdout, format, findings); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	if len(findings) > 0 {
		os.Exit(1)
	}
}
