package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/glsec/glsec/internal/cache"
	"github.com/glsec/glsec/internal/color"
	"github.com/glsec/glsec/internal/config"
	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/output"
	"github.com/glsec/glsec/internal/parser"
	"github.com/glsec/glsec/internal/shellcheck"
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
	if len(os.Args) >= 2 && os.Args[1] == "explain" {
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: glsec explain <RULE-ID>")
			os.Exit(2)
		}
		noColor := false
		ruleID := ""
		for _, arg := range os.Args[2:] {
			switch arg {
			case "--no-color", "-no-color":
				noColor = true
			default:
				if !strings.HasPrefix(arg, "-") && ruleID == "" {
					ruleID = arg
				}
			}
		}
		if ruleID == "" {
			fmt.Fprintln(os.Stderr, "usage: glsec explain <RULE-ID>")
			os.Exit(2)
		}
		runExplain(ruleID, noColor)
		return
	}

	formatFlag := flag.String("format", "text", "output format: text, json, sarif, codeclimate")
	configFlag := flag.String("config", config.DefaultFile, "path to .glsec.yml config file")
	versionFlag := flag.Bool("version", false, "print version and exit")
	gitlabVersionFlag := flag.String("gitlab-version", "", "target GitLab version, e.g. 16.0 (skips rules not available in that version)")
	strictFlag := flag.Bool("strict", false, "treat warn findings as errors for the exit code (output severity is unchanged)")
	noExitCodesFlag := flag.Bool("no-exit-codes", false, "always exit 0 on successful execution, regardless of findings")
	generateIgnoreFlag := flag.Bool("generate-ignore", false, "write all current findings to .glsec-ignore as a baseline and exit 0")
	noCacheFlag := flag.Bool("no-cache", false, "disable result cache for this run")
	clearCacheFlag := flag.Bool("clear-cache", false, "remove all cached results and exit")
	noColorFlag := flag.Bool("no-color", false, "disable colored output")
	var excludeArgs []string
	flag.Func("exclude", "exclude a file or glob pattern from scanning (may be repeated)", func(s string) error {
		excludeArgs = append(excludeArgs, s)
		return nil
	})
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: glsec [flags] [file]")
		fmt.Fprintln(os.Stderr, "       glsec explain <RULE-ID>")
		fmt.Fprintln(os.Stderr, "       If no file is given, glsec looks for .gitlab-ci.yml in the current directory.")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *versionFlag {
		fmt.Printf("glsec %s (commit %s, built %s)\n", resolvedVersion(), commit, date)
		return
	}

	if *clearCacheFlag {
		if err := cache.Clear(); err != nil {
			fmt.Fprintf(os.Stderr, "error: --clear-cache: %v\n", err)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "cache cleared")
		return
	}

	if flag.NArg() > 1 {
		flag.Usage()
		os.Exit(2)
	}

	format, ok := output.ParseFormat(*formatFlag)
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown format %q — use text, json, sarif, or codeclimate\n", *formatFlag)
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

	// Collect all pipeline documents first so we can build a complete cache key.
	seen := map[string]bool{}
	if abs, absErr := filepath.Abs(file); absErr == nil {
		seen[abs] = true
	}
	allDocs := collectDocuments(doc, file, cfg.ExcludePaths, seen)

	// Compute job count across all documents.
	jobCount := parser.CountJobs(doc.Root)
	for _, d := range allDocs[1:] {
		jobCount += parser.CountJobs(d.Root)
	}

	colorEnabled := color.IsEnabled(*noColorFlag, os.Stdout)

	// Cache lookup (skipped for --generate-ignore since it writes new state).
	useCache := !*noCacheFlag && !*generateIgnoreFlag
	var cacheKey string
	if useCache {
		filePaths := make([]string, len(allDocs))
		for i, d := range allDocs {
			filePaths[i] = d.File
		}
		cacheKey, err = cache.Key(resolvedVersion(), gitlabVersionStr, filePaths, *configFlag, suppress.IgnoreFile, cfg.ExcludePaths)
		if err == nil {
			if entry, ok := cache.Load(cacheKey); ok {
				writeAndExit(os.Stdout, format, entry.Findings, entry.JobCount, cfg, colorEnabled)
			}
		}
	}

	// Cache miss — run rules across all collected documents.
	var findings []finding.Finding
	for _, d := range allDocs {
		findings = append(findings, collectFindings(d, d.File, cfg, gitlabVersion, *generateIgnoreFlag)...)
	}

	if *generateIgnoreFlag {
		if err := writeIgnoreFile(suppress.IgnoreFile, findings); err != nil {
			fmt.Fprintf(os.Stderr, "error: --generate-ignore: %v\n", err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "wrote %d suppression(s) to %s\n", len(findings), suppress.IgnoreFile)
		return // exit 0
	}

	if useCache && cacheKey != "" {
		cache.Store(cacheKey, &cache.Entry{Findings: findings, JobCount: jobCount})
	}

	writeAndExit(os.Stdout, format, findings, jobCount, cfg, colorEnabled)
}

func writeAndExit(w *os.File, format output.Format, findings []finding.Finding, jobCount int, cfg *config.Config, colorEnabled bool) {
	var writeErr error
	switch format {
	case output.FormatSARIF:
		writeErr = output.WriteSARIF(w, findings, rules.CWEID, rules.CWEName, rules.OWASPCategories, rules.OWASPCategoryName)
	case output.FormatJSON:
		writeErr = output.WriteJSON(w, findings, rules.OWASPCategories)
	default:
		writeErr = output.Write(w, format, findings, jobCount, colorEnabled)
	}
	if writeErr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", writeErr)
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

func resolvedVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
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

// collectDocuments recursively collects all pipeline documents (main + children)
// without running any rules. The first element is always the root document.
func collectDocuments(doc *parser.Document, path string, excludePaths []string, seen map[string]bool) []*parser.Document {
	all := []*parser.Document{doc}
	baseDir := filepath.Dir(path)
	for _, child := range parser.ChildPipelinePaths(doc.Root) {
		childPath := filepath.Join(baseDir, child)
		if matchesExclude(childPath, excludePaths) {
			continue
		}
		abs, err := filepath.Abs(childPath)
		if err != nil || seen[abs] {
			continue
		}
		seen[abs] = true
		childDoc, err := parser.ParseFile(childPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: child pipeline %s: %v\n", childPath, err)
			continue
		}
		all = append(all, collectDocuments(childDoc, childPath, excludePaths, seen)...)
	}
	return all
}

// collectFindings runs all applicable rules against doc and returns the findings.
func collectFindings(doc *parser.Document, path string, cfg *config.Config, gitlabVersion gitlabver.Version, generateIgnore bool) []finding.Finding {
	sm := suppress.Build(doc.Root)
	sm.Merge(suppress.LoadIgnoreFile(suppress.IgnoreFile, path))

	var findings []finding.Finding
	for _, rule := range rules.All() {
		if !cfg.RuleEnabled(rule.ID()) {
			continue
		}
		if !cfg.OWASPEnabled(rules.OWASPCategories(rule.ID())) {
			continue
		}
		if !rules.EnabledFor(rule.ID(), gitlabVersion) {
			continue
		}
		for _, f := range rule.Check(doc.Root, path) {
			f = cfg.ApplySeverity(f)
			if !cfg.AboveMinSeverity(f) {
				continue
			}
			if !generateIgnore && sm.IsSuppressed(f.Line, f.RuleID) {
				continue
			}
			findings = append(findings, f)
		}
	}

	if cfg.ShellCheck.Enabled {
		for _, f := range shellcheck.Run(doc.Root, path, cfg.ShellCheck.Path) {
			if !cfg.RuleEnabled(f.RuleID) {
				continue
			}
			f = cfg.ApplySeverity(f)
			if !cfg.AboveMinSeverity(f) {
				continue
			}
			if !generateIgnore && sm.IsSuppressed(f.Line, f.RuleID) {
				continue
			}
			findings = append(findings, f)
		}
	}

	return findings
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
