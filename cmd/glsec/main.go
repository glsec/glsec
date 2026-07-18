package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/glsec/glsec/internal/baseline"
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
	if len(os.Args) >= 2 && os.Args[1] == "list" {
		runList(os.Args[2:])
		return
	}
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

	formatFlag := flag.String("format", "text", "output format: text, table, json, sarif, codeclimate, junit")
	configFlag := flag.String("config", config.DefaultFile, "path to .glsec.yml config file")
	versionFlag := flag.Bool("version", false, "print version and exit")
	gitlabVersionFlag := flag.String("gitlab-version", "", "target GitLab version, e.g. 16.0 (skips rules not available in that version)")
	strictFlag := flag.Bool("strict", false, "treat warn findings as errors for the exit code (output severity is unchanged)")
	noExitCodesFlag := flag.Bool("no-exit-codes", false, "always exit 0 on successful execution, regardless of findings")
	generateIgnoreFlag := flag.Bool("generate-ignore", false, "write all current findings to .glsec-ignore as a baseline and exit 0")
	noIgnoresFlag := flag.Bool("no-ignores", false, "audit mode: bypass all glsec suppressions (inline # glsec:ignore directives and the .glsec-ignore baseline) for this run; report every finding")
	newOnlyFlag := flag.Bool("new-only", false, "report (and fail) only on findings absent from the baseline; defaults to the .glsec-ignore baseline unless --baseline is given")
	baselineFlag := flag.String("baseline", "", "path to a baseline to diff against in --new-only mode: a glsec JSON snapshot (--format json) or a .glsec-ignore file (implies --new-only)")
	noCacheFlag := flag.Bool("no-cache", false, "disable result cache for this run")
	clearCacheFlag := flag.Bool("clear-cache", false, "remove all cached results and exit")
	noColorFlag := flag.Bool("no-color", false, "disable colored output")
	recursiveFlag := flag.Bool("recursive", false, "recursively scan the given directories for .gitlab-ci.yml files")
	var nameArgs []string
	flag.Func("name", "additional filename/path glob to treat as a CI config during --recursive walks (may be repeated)", func(s string) error {
		nameArgs = append(nameArgs, s)
		return nil
	})
	var excludeArgs []string
	flag.Func("exclude", "exclude a file or glob pattern from scanning (may be repeated)", func(s string) error {
		excludeArgs = append(excludeArgs, s)
		return nil
	})
	var onlyArgs, skipArgs []string
	flag.Func("only", "run only these rule IDs (comma-separated, may be repeated)", func(s string) error {
		onlyArgs = append(onlyArgs, splitRuleIDs(s)...)
		return nil
	})
	flag.Func("skip", "skip these rule IDs (comma-separated, may be repeated)", func(s string) error {
		skipArgs = append(skipArgs, splitRuleIDs(s)...)
		return nil
	})
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: glsec [flags] [file]")
		fmt.Fprintln(os.Stderr, "       glsec explain <RULE-ID>")
		fmt.Fprintln(os.Stderr, "       glsec list [--format text|json] [--owasp CICD-SEC-N]")
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

	format, ok := output.ParseFormat(*formatFlag)
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown format %q — use text, table, json, sarif, codeclimate, or junit\n", *formatFlag)
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

	if len(onlyArgs) > 0 {
		cfg.Only = ruleIDSet(onlyArgs)
		warnUnknownRuleIDs("--only", cfg.Only)
	}
	if len(skipArgs) > 0 {
		cfg.Skip = ruleIDSet(skipArgs)
		warnUnknownRuleIDs("--skip", cfg.Skip)
	}

	rules.GL016.SetTrustedHosts(cfg.TrustedHosts)
	rules.GL065.SetAllowedRegistries(cfg.AllowedRegistries)
	rules.GL075.SetAllowedIncludeSources(cfg.AllowedIncludeSources)

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

	recursivePatterns := append(append([]string{}, cfg.RecursivePatterns...), nameArgs...)
	if len(recursivePatterns) > 0 && !*recursiveFlag {
		fmt.Fprintln(os.Stderr, "warning: --name / recursive_patterns only apply with --recursive; ignoring")
	}

	targets, err := resolveTargets(flag.Args(), *recursiveFlag, recursivePatterns)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	colorEnabled := color.IsEnabled(*noColorFlag, os.Stdout)
	stdoutIsTTY := color.IsTerminal(os.Stdout)
	newOnly := *newOnlyFlag || *baselineFlag != ""
	useCache := !*noCacheFlag && !*generateIgnoreFlag && !*noIgnoresFlag && !newOnly

	scanOpts := scanOptions{
		cfg:            cfg,
		gitlabVersion:  gitlabVersion,
		versionStr:     gitlabVersionStr,
		configPath:     *configFlag,
		only:           onlyArgs,
		skip:           skipArgs,
		useCache:       useCache,
		generateIgnore: *generateIgnoreFlag,
		noIgnores:      *noIgnoresFlag,
		newOnly:        newOnly,
	}

	var allFindings []finding.Finding
	totalJobCount := 0
	hadError := false
	for _, file := range targets {
		if matchesExclude(file, cfg.ExcludePaths) {
			continue
		}
		findings, jobCount, ok := scanRoot(file, scanOpts)
		if !ok {
			hadError = true
			continue
		}
		allFindings = append(allFindings, findings...)
		totalJobCount += jobCount
	}

	if *generateIgnoreFlag {
		if err := writeIgnoreFile(suppress.IgnoreFile, allFindings); err != nil {
			fmt.Fprintf(os.Stderr, "error: --generate-ignore: %v\n", err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "wrote %d suppression(s) to %s\n", len(allFindings), suppress.IgnoreFile)
		return // exit 0
	}

	if newOnly {
		allFindings = filterNewOnly(allFindings, *baselineFlag)
	}

	if err := writeOutput(os.Stdout, format, allFindings, totalJobCount, colorEnabled, stdoutIsTTY); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	if hadError {
		os.Exit(2)
	}
	os.Exit(exitCode(allFindings, cfg))
}

type scanOptions struct {
	cfg            *config.Config
	gitlabVersion  gitlabver.Version
	versionStr     string
	configPath     string
	only           []string
	skip           []string
	useCache       bool
	generateIgnore bool
	noIgnores      bool
	newOnly        bool
}

// scanRoot parses one root pipeline file (and its child pipelines), runs the
// rules, and returns the findings and job count. ok is false if the file could
// not be parsed or validated; the error has already been reported to stderr.
func scanRoot(file string, opt scanOptions) (findings []finding.Finding, jobCount int, ok bool) {
	doc, err := parser.ParseFile(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return nil, 0, false
	}

	warns, valErr := validate.File(file, doc)
	for _, w := range warns {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}
	if valErr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", valErr)
		return nil, 0, false
	}

	seen := map[string]bool{}
	if abs, absErr := filepath.Abs(file); absErr == nil {
		seen[abs] = true
	}
	allDocs := collectDocuments(doc, file, opt.cfg.ExcludePaths, seen)

	jobCount = parser.CountJobs(doc.Root)
	for _, d := range allDocs[1:] {
		jobCount += parser.CountJobs(d.Root)
	}

	var cacheKey string
	if opt.useCache {
		filePaths := make([]string, len(allDocs))
		for i, d := range allDocs {
			filePaths[i] = d.File
		}
		if key, kerr := cache.Key(resolvedVersion(), opt.versionStr, filePaths, opt.configPath, suppress.IgnoreFile, opt.cfg.ExcludePaths, opt.only, opt.skip); kerr == nil {
			cacheKey = key
			if entry, hit := cache.Load(cacheKey); hit {
				return entry.Findings, entry.JobCount, true
			}
		}
	}

	skipSuppress := opt.generateIgnore || opt.noIgnores
	for _, d := range allDocs {
		findings = append(findings, collectFindings(d, d.File, opt.cfg, opt.gitlabVersion, skipSuppress, opt.newOnly)...)
	}

	if opt.useCache && cacheKey != "" {
		cache.Store(cacheKey, &cache.Entry{Findings: findings, JobCount: jobCount})
	}

	return findings, jobCount, true
}

// writeOutput renders findings in the requested format.
func writeOutput(w *os.File, format output.Format, findings []finding.Finding, jobCount int, colorEnabled, isTTY bool) error {
	switch format {
	case output.FormatSARIF:
		return output.WriteSARIF(w, findings, rules.CWEID, rules.CWEName, rules.OWASPCategories, rules.OWASPCategoryName, rules.ASVSRequirements, rules.ASVSRequirementName)
	case output.FormatJSON:
		return output.WriteJSON(w, findings, rules.OWASPCategories, rules.ASVSRequirements)
	default:
		return output.Write(w, format, findings, jobCount, colorEnabled, isTTY)
	}
}

// exitCode returns the process exit code for the given findings and config:
// 1 if any error finding (or any warn finding under --strict), else 0.
func exitCode(findings []finding.Finding, cfg *config.Config) int {
	if cfg.NoExitCodes {
		return 0
	}
	for _, f := range findings {
		if f.Severity == finding.Error {
			return 1
		}
		if cfg.Strict && f.Severity == finding.Warn {
			return 1
		}
	}
	return 0
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

// splitRuleIDs splits a comma-separated rule list, trims and upper-cases each
// entry, and drops empties.
func splitRuleIDs(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if id := strings.ToUpper(strings.TrimSpace(part)); id != "" {
			out = append(out, id)
		}
	}
	return out
}

// ruleIDSet builds a set from a list of rule IDs.
func ruleIDSet(ids []string) map[string]bool {
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set
}

// warnUnknownRuleIDs prints a stderr warning for any ID in set that is not a
// known rule, so typos (e.g. --only GL01) do not silently match nothing.
func warnUnknownRuleIDs(flagName string, set map[string]bool) {
	known := make(map[string]bool, len(rules.All()))
	for _, r := range rules.All() {
		known[r.ID()] = true
	}
	for id := range set {
		if !known[id] {
			fmt.Fprintf(os.Stderr, "warning: %s: unknown rule ID %q\n", flagName, id)
		}
	}
}

// resolveTargets turns the positional arguments into a list of pipeline files
// to scan. Without --recursive: each argument is used as a literal file if it
// exists, otherwise expanded as a glob; with no arguments it falls back to
// .gitlab-ci.yml in the current directory. With --recursive: each argument (or
// "." if none) is walked for files named .gitlab-ci.yml plus any extra
// patterns.
func resolveTargets(args []string, recursive bool, patterns []string) ([]string, error) {
	if recursive {
		for _, p := range patterns {
			if _, err := filepath.Match(p, ""); err != nil {
				return nil, fmt.Errorf("invalid --name pattern %q: %w", p, err)
			}
		}
		dirs := args
		if len(dirs) == 0 {
			dirs = []string{"."}
		}
		var out []string
		for _, d := range dirs {
			files, err := walkForCIFiles(d, patterns)
			if err != nil {
				return nil, err
			}
			out = append(out, files...)
		}
		if len(out) == 0 {
			what := ".gitlab-ci.yml files"
			if len(patterns) > 0 {
				what = "matching CI config files"
			}
			return nil, fmt.Errorf("no %s found under %s", what, strings.Join(dirs, ", "))
		}
		return dedupeStrings(out), nil
	}

	if len(args) == 0 {
		const defaultCI = ".gitlab-ci.yml"
		if _, err := os.Stat(defaultCI); err != nil {
			return nil, fmt.Errorf("no .gitlab-ci.yml found in current directory — pass a file path explicitly")
		}
		return []string{defaultCI}, nil
	}

	var out []string
	for _, a := range args {
		if _, err := os.Stat(a); err == nil {
			out = append(out, a)
			continue
		}
		if matches, _ := filepath.Glob(a); len(matches) > 0 {
			out = append(out, matches...)
			continue
		}
		return nil, fmt.Errorf("no such file or glob match: %s", a)
	}
	return dedupeStrings(out), nil
}

// walkForCIFiles returns all CI config files under dir, skipping .git
// directories. A file matches if its basename is .gitlab-ci.yml or if it
// matches one of the extra patterns: a pattern without "/" is matched against
// the basename, one with "/" against the path relative to dir.
func walkForCIFiles(dir string, patterns []string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if matchesCIFile(dir, path, d.Name(), patterns) {
			out = append(out, path)
		}
		return nil
	})
	return out, err
}

// matchesCIFile reports whether a walked file should be treated as a CI config.
func matchesCIFile(dir, path, base string, patterns []string) bool {
	if base == ".gitlab-ci.yml" {
		return true
	}
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		rel = path
	}
	rel = filepath.ToSlash(rel)
	for _, p := range patterns {
		target := base
		if strings.Contains(p, "/") {
			target = rel
		}
		if ok, _ := filepath.Match(filepath.ToSlash(p), target); ok {
			return true
		}
	}
	return false
}

func dedupeStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
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
// skipIgnoreFile drops the .glsec-ignore line suppression (but keeps inline
// directives) so --new-only can diff the full backlog against the baseline by
// fingerprint instead of by exact line.
func collectFindings(doc *parser.Document, path string, cfg *config.Config, gitlabVersion gitlabver.Version, skipSuppress, skipIgnoreFile bool) []finding.Finding {
	sm := suppress.Build(doc.Root)
	if !skipIgnoreFile {
		sm.Merge(suppress.LoadIgnoreFile(suppress.IgnoreFile, path))
	}

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
			if !skipSuppress && sm.IsSuppressed(f.Line, f.RuleID) {
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
			if !skipSuppress && sm.IsSuppressed(f.Line, f.RuleID) {
				continue
			}
			findings = append(findings, f)
		}
	}

	return findings
}

// filterNewOnly keeps only findings absent from the baseline. baselinePath is
// empty for the default .glsec-ignore baseline (a missing default is treated as
// an empty baseline — everything is new); an explicit --baseline that cannot be
// read is a fatal error. The number of baselined findings is reported to stderr.
func filterNewOnly(findings []finding.Finding, baselinePath string) []finding.Finding {
	path := baselinePath
	if path == "" {
		path = suppress.IgnoreFile
	}
	bl, err := baseline.Load(path)
	if err != nil {
		if baselinePath == "" && os.IsNotExist(err) {
			bl = baseline.Empty()
		} else {
			fmt.Fprintf(os.Stderr, "error: --baseline: %v\n", err)
			os.Exit(2)
		}
	}

	newFindings := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		if bl.IsNew(f) {
			newFindings = append(newFindings, f)
		}
	}
	if n := len(findings) - len(newFindings); n > 0 {
		fmt.Fprintf(os.Stderr, "%d finding(s) matched the baseline and were not reported\n", n)
	}
	return newFindings
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
