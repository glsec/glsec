package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	strictFlag := flag.Bool("strict", false, "treat warn findings as errors for the exit code (output severity is unchanged)")
	noExitCodesFlag := flag.Bool("no-exit-codes", false, "always exit 0 on successful execution, regardless of findings")
	generateIgnoreFlag := flag.Bool("generate-ignore", false, "write all current findings to .glsec-ignore as a baseline and exit 0")
	var excludeArgs []string
	flag.Func("exclude", "exclude a file or glob pattern from scanning (may be repeated)", func(s string) error {
		excludeArgs = append(excludeArgs, s)
		return nil
	})
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: glsec [flags] [file]")
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

	// CLI flags take precedence over config file values.
	if *strictFlag {
		cfg.Strict = true
	}
	if *noExitCodesFlag {
		cfg.NoExitCodes = true
	}
	cfg.ExcludePaths = append(cfg.ExcludePaths, excludeArgs...)

	rules.GL016.SetTrustedHosts(cfg.TrustedHosts)

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

	if matchesExclude(file, cfg.ExcludePaths) {
		return // file is excluded — exit 0 with no output
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
	suppressMap.Merge(suppress.LoadIgnoreFile(suppress.IgnoreFile, file))

	var findings []finding.Finding
	for _, rule := range rules.All() {
		if !cfg.RuleEnabled(rule.ID()) {
			continue
		}
		if !rules.EnabledFor(rule.ID(), gitlabVersion) {
			continue
		}
		for _, f := range rule.Check(doc.Root, file) {
			f = cfg.ApplySeverity(f)
			if !cfg.AboveMinSeverity(f) {
				continue
			}
			if !*generateIgnoreFlag && suppressMap.IsSuppressed(f.Line, f.RuleID) {
				continue
			}
			findings = append(findings, f)
		}
	}

	if *generateIgnoreFlag {
		if err := writeIgnoreFile(suppress.IgnoreFile, findings); err != nil {
			fmt.Fprintf(os.Stderr, "error: --generate-ignore: %v\n", err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "wrote %d suppression(s) to %s\n", len(findings), suppress.IgnoreFile)
		return // exit 0
	}

	if err := output.Write(os.Stdout, format, findings); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	if cfg.NoExitCodes {
		return
	}
	for _, f := range findings {
		if f.Severity == finding.Error {
			os.Exit(1)
		}
		if cfg.Strict && f.Severity == finding.Warn {
			os.Exit(1)
		}
	}
}

// matchesExclude returns true if file matches any of the given patterns.
// Supports filepath.Match globs, directory suffixes (/ or /**), and exact paths.
func matchesExclude(file string, patterns []string) bool {
	clean := filepath.ToSlash(filepath.Clean(file))
	for _, pat := range patterns {
		// Directory pattern: "vendor/" or "infra/old/**"
		if strings.HasSuffix(pat, "/") || strings.HasSuffix(pat, "/**") {
			dir := filepath.ToSlash(filepath.Clean(strings.TrimSuffix(strings.TrimSuffix(pat, "**"), "/")))
			if strings.HasPrefix(clean, dir+"/") || clean == dir {
				return true
			}
			continue
		}
		if ok, _ := filepath.Match(pat, clean); ok {
			return true
		}
		// Also try matching the pattern against the slash-normalised path.
		if ok, _ := filepath.Match(filepath.ToSlash(pat), clean); ok {
			return true
		}
	}
	return false
}

// writeIgnoreFile creates or overwrites .glsec-ignore with one entry per finding.
func writeIgnoreFile(path string, findings []finding.Finding) error {
	lines := []string{"# Generated by glsec --generate-ignore"}
	for _, f := range findings {
		lines = append(lines, fmt.Sprintf("%s:%d %s", f.File, f.Line, f.RuleID))
	}
	content := strings.Join(lines, "\n") + "\n"
	return os.WriteFile(path, []byte(content), 0600) //nolint:gosec
}
