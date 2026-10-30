// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/glsec/glsec/internal/baseline"
	"github.com/glsec/glsec/internal/cache"
	"github.com/glsec/glsec/internal/color"
	"github.com/glsec/glsec/internal/config"
	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/output"
	"github.com/glsec/glsec/internal/parser"
	"github.com/glsec/glsec/internal/redact"
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
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the whole CLI: it parses args, scans, writes the report to stdout and
// returns the process exit code instead of exiting, so tests can drive it.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) >= 1 && args[0] == "list" {
		return runList(args[1:], stdout, stderr)
	}
	if len(args) >= 1 && args[0] == "inventory" {
		return runInventory(args[1:], stdout, stderr)
	}
	if len(args) >= 1 && args[0] == "explain" {
		return runExplainArgs(args[1:], stdout, stderr)
	}

	flags := flag.NewFlagSet("glsec", flag.ContinueOnError)
	flags.SetOutput(stderr)

	formatFlag := flags.String("format", "text", "output format: text, table, json, sarif, codeclimate, junit, gitlab-sast")
	configFlag := flags.String("config", config.DefaultFile, "path to .glsec.yml config file")
	versionFlag := flags.Bool("version", false, "print version and exit")
	gitlabVersionFlag := flags.String("gitlab-version", "", "target GitLab version, e.g. 16.0 (skips rules not available in that version)")
	strictFlag := flags.Bool("strict", false, "treat warn findings as errors for the exit code (output severity is unchanged)")
	noExitCodesFlag := flags.Bool("no-exit-codes", false, "always exit 0 on successful execution, regardless of findings")
	generateIgnoreFlag := flags.Bool("generate-ignore", false, "write all current findings to .glsec-ignore as a baseline and exit 0")
	noRepoConfigFlag := flags.Bool("no-repo-config", false, "ignore a .glsec.yml in the working directory; only a file passed with --config is read")
	noIgnoresFlag := flags.Bool("no-ignores", false, "audit mode: bypass all glsec suppressions (inline # glsec:ignore directives and the .glsec-ignore baseline) for this run; report every finding")
	newOnlyFlag := flags.Bool("new-only", false, "report (and fail) only on findings absent from the baseline; defaults to the .glsec-ignore baseline unless --baseline is given")
	baselineFlag := flags.String("baseline", "", "path to a baseline to diff against in --new-only mode: a glsec JSON snapshot (--format json) or a .glsec-ignore file (implies --new-only)")
	requireReasonFlag := flags.Bool("require-ignore-reason", false, "treat an inline # glsec:ignore without a \"-- reason\" as a policy violation (exit 2)")
	noCacheFlag := flags.Bool("no-cache", false, "disable result cache for this run")
	// Only a flag: .glsec.yml comes from the scanned repository, which must
	// not be able to turn masking off (#831).
	noRedactFlag := flags.Bool("no-redact", false, "show secret values in findings and source lines instead of masking them (local debugging only)")
	cacheFlag := flags.Bool("cache", false, "use the result cache in CI (CI=true), where it is off by default; --no-cache wins")
	clearCacheFlag := flags.Bool("clear-cache", false, "remove all cached results and exit")
	noColorFlag := flags.Bool("no-color", false, "disable colored output")
	shellcheckPathFlag := flags.String("shellcheck-path", "", "path to the ShellCheck binary (default: shellcheck from PATH)")
	recursiveFlag := flags.Bool("recursive", false, "recursively scan the given directories for .gitlab-ci.yml files")
	var nameArgs []string
	flags.Func("name", "additional filename/path glob to treat as a CI config during --recursive walks (may be repeated)", func(s string) error {
		nameArgs = append(nameArgs, s)
		return nil
	})
	var excludeArgs []string
	flags.Func("exclude", "exclude a file or glob pattern from scanning (may be repeated)", func(s string) error {
		excludeArgs = append(excludeArgs, s)
		return nil
	})
	var onlyArgs, skipArgs []string
	flags.Func("only", "run only these rule IDs (comma-separated, may be repeated)", func(s string) error {
		onlyArgs = append(onlyArgs, splitRuleIDs(s)...)
		return nil
	})
	flags.Func("skip", "skip these rule IDs (comma-separated, may be repeated)", func(s string) error {
		skipArgs = append(skipArgs, splitRuleIDs(s)...)
		return nil
	})
	flags.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "usage: glsec [flags] [file]")
		_, _ = fmt.Fprintln(stderr, "       glsec explain <RULE-ID>")
		_, _ = fmt.Fprintln(stderr, "       glsec list [--format text|json] [--owasp CICD-SEC-N]")
		_, _ = fmt.Fprintln(stderr, "       glsec inventory [--format cyclonedx] [file]")
		_, _ = fmt.Fprintln(stderr, "       If no file is given, glsec looks for .gitlab-ci.yml in the current directory.")
		_, _ = fmt.Fprintln(stderr, "       Flags may appear before or after files; -- ends flag parsing.")
		flags.PrintDefaults()
	}
	if err := parseFlags(flags, args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	if *versionFlag {
		_, _ = fmt.Fprintf(stdout, "glsec %s (commit %s, built %s)\n", resolvedVersion(), commit, date)
		return 0
	}

	if *clearCacheFlag {
		if err := cache.Clear(); err != nil {
			_, _ = fmt.Fprintf(stderr, "error: --clear-cache: %v\n", err)
			return 2
		}
		_, _ = fmt.Fprintln(stderr, "cache cleared")
		return 0
	}

	format, ok := output.ParseFormat(*formatFlag)
	if !ok {
		_, _ = fmt.Fprintf(stderr, "unknown format %q — use text, table, json, sarif, codeclimate, junit, or gitlab-sast\n", *formatFlag)
		return 2
	}

	// A .glsec.yml in the working directory usually comes from the repository
	// being scanned. When that repository is untrusted, its config must not
	// decide which rules run or what counts as a failure.
	configPath := *configFlag
	if *noRepoConfigFlag && !flagSet(flags, "config") {
		if _, err := os.Stat(config.DefaultFile); err == nil {
			_, _ = fmt.Fprintf(stderr, "note: %s is ignored (--no-repo-config)\n", config.DefaultFile)
		}
		configPath = ""
	}
	// .glsec.yml and .glsec-ignore in the working directory come from the
	// repository being scanned. A symbolic link out of it would make glsec read
	// another file, or with --generate-ignore overwrite it.
	repoFiles := []struct {
		path string
		used bool
	}{
		{config.DefaultFile, configPath == config.DefaultFile && !flagSet(flags, "config")},
		{suppress.IgnoreFile, !*noIgnoresFlag || *generateIgnoreFlag},
	}
	for _, f := range repoFiles {
		if f.used && !withinRoot(".", f.path) {
			_, _ = fmt.Fprintf(stderr, "error: %s: symbolic link to a file outside the working directory\n", f.path)
			return 2
		}
	}

	cfg := config.Default()
	if configPath != "" {
		var err error
		if cfg, err = config.Load(configPath); err != nil {
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
			return 2
		}
	}

	// CLI flags take precedence over config file values.
	if *strictFlag {
		cfg.Strict = true
	}
	if *noExitCodesFlag {
		cfg.NoExitCodes = true
	}
	if *requireReasonFlag {
		cfg.RequireIgnoreReason = true
	}
	cfg.ExcludePaths = append(cfg.ExcludePaths, excludeArgs...)

	// A .glsec.yml found in the working directory usually belongs to the
	// repository being scanned, which may be untrusted: a binary path from it
	// would let that repository run code (GHSA-pfj6-q8r7-c768).
	if cfg.ShellCheck.Path != "" && !flagSet(flags, "config") {
		_, _ = fmt.Fprintf(stderr, "warning: %s: shellcheck.path is ignored in a config file glsec finds by itself; use --shellcheck-path, or pass the file with --config\n", config.DefaultFile)
		cfg.ShellCheck.Path = ""
	}
	if *shellcheckPathFlag != "" {
		cfg.ShellCheck.Path = *shellcheckPathFlag
	}

	// A typo in --skip leaves the rule running; a typo in --only drops a
	// rule the user asked for and, alone, turns the scan off with exit 0 (#900).
	if len(onlyArgs) > 0 {
		cfg.Only = ruleIDSet(onlyArgs)
		if unknown := unknownRuleIDs(cfg.Only); len(unknown) > 0 {
			_, _ = fmt.Fprintf(stderr, "error: --only: unknown rule ID %s\n", strings.Join(unknown, ", "))
			return 2
		}
	}
	if len(skipArgs) > 0 {
		cfg.Skip = ruleIDSet(skipArgs)
		for _, id := range unknownRuleIDs(cfg.Skip) {
			_, _ = fmt.Fprintf(stderr, "warning: --skip: unknown rule ID %s\n", id)
		}
	}
	if len(cfg.Only) > 0 && !anyRuleSelected(cfg) {
		_, _ = fmt.Fprintf(stderr, "error: --only and --skip together leave no rule to run\n")
		return 2
	}

	rules.GL016.SetTrustedHosts(cfg.TrustedHosts)
	rules.GL001.SetRequireImageDigest(cfg.RequireImageDigest)
	rules.GL065.SetAllowedRegistries(cfg.AllowedRegistries)
	rules.GL075.SetAllowedIncludeSources(cfg.AllowedIncludeSources)

	// --gitlab-version flag overrides the config file value.
	gitlabVersionStr := cfg.GitLabVersion
	if *gitlabVersionFlag != "" {
		gitlabVersionStr = *gitlabVersionFlag
	}
	gitlabVersion, err := gitlabver.Parse(gitlabVersionStr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: --gitlab-version: %v\n", err)
		return 2
	}
	if !gitlabVersion.IsZero() && !gitlabVersion.AtLeast(gitlabver.Minimum) {
		_, _ = fmt.Fprintf(stderr, "warning: gitlab-version %s is below the minimum supported version %s\n", gitlabVersion, gitlabver.Minimum)
	}

	recursivePatterns := append(append([]string{}, cfg.RecursivePatterns...), nameArgs...)
	if len(recursivePatterns) > 0 && !*recursiveFlag {
		_, _ = fmt.Fprintln(stderr, "warning: --name / recursive_patterns only apply with --recursive; ignoring")
	}

	targets, err := resolveTargets(flags.Args(), *recursiveFlag, recursivePatterns)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %s\n", output.Sanitize(err.Error()))
		return 2
	}

	colorEnabled := color.IsEnabled(*noColorFlag, stdout)
	stdoutIsTTY := color.IsTerminal(stdout)
	newOnly := *newOnlyFlag || *baselineFlag != ""
	// The reason check runs while collecting findings, so a cache hit would skip
	// it and silently drop the per-suppression messages. Opt-in policy, so paying
	// with a cold scan is the right trade.
	useCache := !*noCacheFlag && !*generateIgnoreFlag && !*noIgnoresFlag && !newOnly && !cfg.RequireIgnoreReason
	// A CI job starts fresh, so the cache only helps if the project persists
	// it between pipelines, which costs more than the scan and shares a file
	// that decides what glsec reports (#898).
	if os.Getenv("CI") == "true" && !*cacheFlag {
		useCache = false
	}

	scanOpts := scanOptions{
		stderr:         stderr,
		cfg:            cfg,
		gitlabVersion:  gitlabVersion,
		versionStr:     gitlabVersionStr,
		configPath:     configPath,
		only:           onlyArgs,
		skip:           skipArgs,
		useCache:       useCache,
		generateIgnore: *generateIgnoreFlag,
		scannedFiles:   map[string]bool{},
		included:       map[string]bool{},
		noIgnores:      *noIgnoresFlag,
		newOnly:        newOnly,
	}

	var allFindings []finding.Finding
	totalJobCount := 0
	totalUnjustified := 0
	// The reports carry the errors too, so a failed scan doesn't look like a
	// clean one (#809).
	var scanErrors []output.ScanError
	scanned := 0
	for _, file := range targets {
		if matchesExclude(file, cfg.ExcludePaths) {
			continue
		}
		scanned++
		// Already scanned as part of an earlier pipeline that includes it,
		// with that pipeline's configuration around it (#810).
		if abs, err := filepath.Abs(file); err == nil && scanOpts.included[abs] {
			continue
		}
		findings, jobCount, unjustified, scanErr := scanRoot(file, scanOpts)
		if scanErr != nil {
			_, _ = fmt.Fprintf(stderr, "error: %s\n", scanErr.Message)
			scanErrors = append(scanErrors, *scanErr)
			continue
		}
		allFindings = append(allFindings, findings...)
		totalJobCount += jobCount
		totalUnjustified += unjustified
	}

	// Excluding every file looks exactly like a clean scan, and the exclusions
	// usually come from the repository being scanned.
	if len(targets) > 0 && scanned == 0 {
		const msg = "every file to scan matches exclude_paths or --exclude; nothing was scanned"
		severity := "warning"
		if cfg.Strict {
			severity = "error"
			scanErrors = append(scanErrors, output.ScanError{Message: msg})
		}
		_, _ = fmt.Fprintf(stderr, "%s: %s\n", severity, msg)
	}

	if *generateIgnoreFlag {
		ruleDidRun := func(id string) bool { return ruleRan(cfg, gitlabVersion, id) }
		written, kept, err := writeIgnoreFile(suppress.IgnoreFile, allFindings, scanOpts.scannedFiles, ruleDidRun)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: --generate-ignore: %v\n", err)
			return 2
		}
		_, _ = fmt.Fprintf(stderr, "wrote %d suppression(s) to %s\n", written, suppress.IgnoreFile)
		if kept > 0 {
			_, _ = fmt.Fprintf(stderr, "kept %d other suppression(s) for rules or files this run didn't scan\n", kept)
		}
		return 0
	}

	if newOnly {
		var err error
		if allFindings, err = filterNewOnly(stderr, allFindings, *baselineFlag); err != nil {
			_, _ = fmt.Fprintf(stderr, "error: --baseline: %v\n", err)
			return 2
		}
	}

	if err := writeOutput(stdout, format, allFindings, scanErrors, totalJobCount, colorEnabled, stdoutIsTTY, !*noRedactFlag); err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
		return 2
	}

	if len(scanErrors) > 0 {
		return 2
	}
	if totalUnjustified > 0 {
		_, _ = fmt.Fprintf(stderr, "%d suppression(s) without a reason; require_ignore_reason is enabled\n", totalUnjustified)
		return 2
	}
	return exitCode(allFindings, cfg)
}

type scanOptions struct {
	stderr         io.Writer
	cfg            *config.Config
	gitlabVersion  gitlabver.Version
	versionStr     string
	configPath     string
	only           []string
	skip           []string
	useCache       bool
	generateIgnore bool
	// scannedFiles collects every pipeline file scanned, child pipelines
	// included, for --generate-ignore; nil otherwise.
	scannedFiles map[string]bool
	// included collects the absolute paths of the files scanned because a
	// pipeline includes them with include: local.
	included  map[string]bool
	noIgnores bool
	newOnly   bool
}

// scanRoot parses one root pipeline file (and its child pipelines), runs the
// rules, and returns the findings and job count, or the error if the file
// could not be scanned. The error's message is sanitized for the terminal.
func scanRoot(file string, opt scanOptions) (findings []finding.Finding, jobCount, unjustified int, scanErr *output.ScanError) {
	fail := func(path string, err error) (findings []finding.Finding, jobCount, unjustified int, scanErr *output.ScanError) {
		return nil, 0, 0, &output.ScanError{File: path, Message: output.Sanitize(err.Error())}
	}
	// Child pipelines must stay inside the directory of the pipeline file, and
	// so must the file itself: a symbolic link out of it would make glsec read
	// and quote a file outside the repository.
	if !withinRoot(filepath.Dir(file), file) {
		return fail(file, fmt.Errorf("%s: symbolic link to a file outside its directory", file))
	}
	doc, err := parser.ParseFile(file)
	if err != nil {
		return fail(file, err)
	}

	warns, valErr := validate.File(file, doc)
	for _, w := range warns {
		_, _ = fmt.Fprintf(opt.stderr, "warning: %s\n", output.Sanitize(w))
	}
	if valErr != nil {
		return fail(file, valErr)
	}

	seen := map[string]bool{}
	if abs, absErr := filepath.Abs(file); absErr == nil {
		seen[abs] = true
	}
	// GitLab resolves trigger:include paths from the repository root, taken
	// here as the directory of the pipeline being scanned.
	allDocs := collectDocuments(opt.stderr, doc, filepath.Dir(file), opt.cfg.ExcludePaths, seen)
	if opt.scannedFiles != nil {
		for _, d := range allDocs {
			opt.scannedFiles[d.File] = true
		}
	}
	for _, d := range allDocs {
		if abs, err := filepath.Abs(d.File); err == nil && d.IncludedBy != nil && opt.included != nil {
			opt.included[abs] = true
		}
	}

	jobCount = parser.CountJobs(doc.Root)
	for _, d := range allDocs[1:] {
		jobCount += parser.CountJobs(d.Root)
	}

	// A cache inside the repository being scanned is under that repository's
	// control: it could ship an entry that makes glsec report nothing.
	useCache := opt.useCache && cache.Dir() != "" && !withinRoot(filepath.Dir(file), cache.Dir())

	var cacheKey string
	if useCache {
		filePaths := make([]string, len(allDocs))
		for i, d := range allDocs {
			filePaths[i] = d.File
		}
		if key, kerr := cache.Key(resolvedVersion(), time.Now().Format("2006-01-02"), opt.versionStr, filePaths, opt.configPath, suppress.IgnoreFile, opt.cfg.ExcludePaths, opt.only, opt.skip); kerr == nil {
			cacheKey = key
			if entry, hit := cache.Load(cacheKey); hit {
				return entry.Findings, entry.JobCount, 0, nil
			}
		}
	}

	skipSuppress := opt.generateIgnore || opt.noIgnores
	for _, d := range withPipelineContext(allDocs) {
		f, u, err := collectFindings(d, d.File, opt.cfg, opt.gitlabVersion, skipSuppress, opt.newOnly)
		if err != nil {
			return fail(d.File, err)
		}
		findings = append(findings, f...)
		unjustified += u
	}

	if useCache && cacheKey != "" {
		cache.Store(cacheKey, &cache.Entry{Findings: findings, JobCount: jobCount})
	}

	return findings, jobCount, unjustified, nil
}

// scanStart is when glsec started, the scan start time in a GitLab SAST report.
var scanStart = time.Now()

// writeOutput renders findings and scan errors in the requested format. With
// mask set, secret values in messages and source lines are masked in every
// format (#831).
func writeOutput(w io.Writer, format output.Format, findings []finding.Finding, errs []output.ScanError, jobCount int, colorEnabled, isTTY, mask bool) error {
	var opts []output.WriteOption
	if mask {
		findings = redact.Findings(findings)
		masked := make([]output.ScanError, len(errs))
		for i, e := range errs {
			masked[i] = output.ScanError{File: e.File, Message: redact.String(e.Message)}
		}
		errs = masked
	} else {
		opts = append(opts, output.NoRedact())
	}
	opts = append(opts, output.WithErrors(errs))
	switch format {
	case output.FormatSARIF:
		return output.WriteSARIF(w, findings, output.SARIFTool{Version: version, Rule: sarifRuleInfo}, rules.CWEID, rules.CWEName, rules.OWASPCategories, rules.OWASPCategoryName, rules.ASVSRequirements, rules.ASVSRequirementName, opts...)
	case output.FormatJSON:
		return output.WriteJSON(w, findings, rules.OWASPCategories, rules.ASVSRequirements, opts...)
	case output.FormatGitLabSAST:
		return output.WriteGitLabSAST(w, findings, output.GitLabSASTMeta{
			Version: version, Rule: sarifRuleInfo, CWE: rules.CWEID,
			OWASP: rules.OWASPCategories, OWASPName: rules.OWASPCategoryName, Start: scanStart,
		}, opts...)
	default:
		return output.Write(w, format, findings, jobCount, colorEnabled, isTTY, opts...)
	}
}

// flagSet reports whether the named flag was given on the command line.
func flagSet(flags *flag.FlagSet, name string) bool {
	set := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
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

// unknownRuleIDs returns the IDs in set that name neither a glsec rule nor a
// ShellCheck check (SCnnnn), quoted and sorted.
func unknownRuleIDs(set map[string]bool) []string {
	known := make(map[string]bool, len(rules.All()))
	for _, r := range rules.All() {
		known[r.ID()] = true
	}
	var out []string
	for id := range set {
		if !known[id] && !shellCheckIDRe.MatchString(id) {
			out = append(out, strconv.Quote(id))
		}
	}
	sort.Strings(out)
	return out
}

var shellCheckIDRe = regexp.MustCompile(`^SC[0-9]{4}$`)

// anyRuleSelected reports whether --only and --skip leave a rule to run.
func anyRuleSelected(cfg *config.Config) bool {
	for id := range cfg.Only {
		if !cfg.Skip[id] {
			return true
		}
	}
	return false
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
		if info, err := os.Stat(a); err == nil {
			if info.IsDir() {
				// Slash form, so the directory form names the file the
				// same way as the explicit file form on every platform:
				// on Windows filepath.Join would give sub\.gitlab-ci.yml
				// while glsec sub/.gitlab-ci.yml reports sub/.gitlab-ci.yml.
				ci := filepath.ToSlash(filepath.Join(a, ".gitlab-ci.yml"))
				if _, err := os.Stat(ci); err != nil {
					if !errors.Is(err, fs.ErrNotExist) {
						return nil, err
					}
					return nil, fmt.Errorf("%s is a directory without a .gitlab-ci.yml — pass the pipeline file", a)
				}
				out = append(out, ci)
				continue
			}
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
		pat = filepath.ToSlash(pat) // a no-op except on Windows, where `vendor\` is a directory too
		// Directory pattern: "vendor/" or "infra/old/**"
		if strings.HasSuffix(pat, "/") || strings.HasSuffix(pat, "/**") {
			dir := filepath.ToSlash(filepath.Clean(strings.TrimSuffix(strings.TrimSuffix(pat, "**"), "/")))
			if strings.HasPrefix(clean, dir+"/") || clean == dir {
				return true
			}
			continue
		}
		// Clean the pattern like the path, so "./legacy/.gitlab-ci.yml" matches
		// too. Both sides use "/" now, so path.Match keeps * from crossing a
		// directory on every OS; filepath.Match would on Windows.
		if ok, _ := path.Match(filepath.ToSlash(filepath.Clean(pat)), clean); ok {
			return true
		}
	}
	return false
}

// collectDocuments recursively collects all pipeline documents (main + children)
// without running any rules. The first element is always the root document.
// Child paths are relative to rootDir at every level, as in GitLab; a missing
// or unparsable child, or one outside rootDir, is reported to w and skipped.
func collectDocuments(w io.Writer, doc *parser.Document, rootDir string, excludePaths []string, seen map[string]bool) []*parser.Document {
	all := []*parser.Document{doc}
	pipeline := doc
	if doc.IncludedBy != nil {
		pipeline = doc.IncludedBy
	}
	follow := func(kind, path string, included bool) {
		childPath := filepath.Join(rootDir, strings.TrimPrefix(path, "/"))
		if matchesExclude(childPath, excludePaths) {
			return
		}
		abs, err := filepath.Abs(childPath)
		if err != nil || seen[abs] {
			return
		}
		seen[abs] = true
		// GitLab rejects local includes outside the project; reading them would
		// let a pipeline file print lines of other files on the runner.
		if !withinRoot(rootDir, childPath) {
			_, _ = fmt.Fprintf(w, "warning: %s %s: outside the repository, skipped\n", kind, output.Sanitize(filepath.ToSlash(childPath)))
			return
		}
		childDoc, err := parser.ParseFile(childPath)
		if err != nil {
			_, _ = fmt.Fprintf(w, "warning: %s %s: %s\n", kind, output.Sanitize(filepath.ToSlash(childPath)), output.Sanitize(err.Error()))
			return
		}
		if included {
			childDoc.IncludedBy = pipeline
		}
		all = append(all, collectDocuments(w, childDoc, rootDir, excludePaths, seen)...)
	}
	for _, child := range parser.ChildPipelinePaths(doc.Root) {
		follow("child pipeline", child, false)
	}
	// Files pulled in with include: local are part of this pipeline (#810).
	for _, include := range parser.LocalIncludePaths(doc.Root) {
		pattern := strings.TrimPrefix(include, "/")
		re := parser.IncludeGlob(pattern)
		if re == nil {
			follow("include", pattern, true)
			continue
		}
		for _, path := range globIncludes(w, rootDir, pattern, re) {
			follow("include", path, true)
		}
	}
	return all
}

// withPipelineContext gives each file of a pipeline the global keywords and
// hidden jobs of the files it includes or is included by (#810), so rules see
// the configuration GitLab merges. A child pipeline is a pipeline of its own.
func withPipelineContext(docs []*parser.Document) []*parser.Document {
	members := map[*parser.Document][]*parser.Document{}
	for _, d := range docs {
		if d.IncludedBy != nil {
			members[d.IncludedBy] = append(members[d.IncludedBy], d)
		}
	}
	if len(members) == 0 {
		return docs
	}
	out := make([]*parser.Document, len(docs))
	for i, d := range docs {
		root := d
		if d.IncludedBy != nil {
			root = d.IncludedBy
		}
		group := append([]*parser.Document{root}, members[root]...)
		others := make([]*parser.Document, 0, len(group)-1)
		for _, o := range group {
			if o != d {
				others = append(others, o)
			}
		}
		out[i] = parser.WithContext(d, others)
	}
	return out
}

// maxIncludes is GitLab's default limit of included files per pipeline.
const maxIncludes = 150

// globIncludes returns the files under rootDir a wildcard include: local
// path matches, relative to rootDir, in lexical order. Symbolic links to
// directories aren't followed, and .git is skipped.
func globIncludes(w io.Writer, rootDir, pattern string, re *regexp.Regexp) []string {
	dir := filepath.Join(rootDir, filepath.FromSlash(parser.IncludeGlobDir(pattern)))
	if !withinRoot(rootDir, dir) {
		_, _ = fmt.Fprintf(w, "warning: include %s: outside the repository, skipped\n", output.Sanitize(pattern))
		return nil
	}
	var paths []string
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable directory has no files to include
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(rootDir, path)
		if err != nil || !re.MatchString(filepath.ToSlash(rel)) {
			return nil
		}
		if len(paths) == maxIncludes {
			_, _ = fmt.Fprintf(w, "warning: include %s: more than %d files match, the rest is skipped\n", output.Sanitize(pattern), maxIncludes)
			return filepath.SkipAll
		}
		paths = append(paths, rel)
		return nil
	})
	return paths
}

// withinRoot reports whether path, after resolving symbolic links, lies inside
// rootDir. For a path that doesn't exist, its nearest existing parent is resolved.
func withinRoot(rootDir, path string) bool {
	root, err := resolvePath(rootDir)
	if err != nil {
		return false
	}
	p, err := resolvePath(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func resolvePath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		return real, nil
	}
	parent := filepath.Dir(abs)
	if parent == abs {
		return abs, nil
	}
	dir, err := resolvePath(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, filepath.Base(abs)), nil
}

// collectFindings runs all applicable rules against doc and returns the findings.
// skipIgnoreFile drops the .glsec-ignore line suppression (but keeps inline
// directives) so --new-only can diff the full backlog against the baseline by
// fingerprint instead of by exact line.
// An unreadable .glsec-ignore comes back as an error: the caller stops the run
// with exit 2, like an unreadable config file, instead of silently scanning
// without the suppressions.
func collectFindings(doc *parser.Document, path string, cfg *config.Config, gitlabVersion gitlabver.Version, skipSuppress, skipIgnoreFile bool) ([]finding.Finding, int, error) {
	sm := suppress.Build(doc.Root)
	// Checked against the inline map only: the .glsec-ignore baseline has no
	// reason column, so requiring one there would be unsatisfiable.
	unjustified := 0
	if cfg.RequireIgnoreReason && !skipSuppress {
		unjustified = reportUnjustified(sm, path)
	}
	if !skipIgnoreFile {
		ignore, err := suppress.LoadIgnoreFile(suppress.IgnoreFile, path)
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %w", suppress.IgnoreFile, err)
		}
		sm.Merge(ignore)
	}
	now := time.Now()

	// keep reports a finding unless an unexpired suppression covers it. An
	// expired suppression is announced, so a finding that suddenly reappears is
	// traceable to the date rather than looking like a new violation.
	keep := func(f finding.Finding) bool {
		// On configuration another file of the pipeline contributes (#810):
		// that file reports it.
		if f.Line <= parser.ContextLine/2 {
			return false
		}
		if skipSuppress {
			return true
		}
		if sm.IsSuppressed(f.Line, f.RuleID, now) {
			return false
		}
		if sm.ExpiredAt(f.Line, f.RuleID, now) {
			fmt.Fprintf(os.Stderr, "%s:%d: %s suppression has expired, reporting the finding again\n", output.Sanitize(path), f.Line, f.RuleID)
		}
		return true
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
		if (doc.ComponentTemplate || doc.IncludedBy != nil) && !rules.AppliesToComponentTemplate(rule.ID()) {
			continue
		}
		for _, f := range rules.Check(rule, doc, path) {
			f = cfg.ApplySeverity(f)
			if !cfg.AboveMinSeverity(f) {
				continue
			}
			if !keep(f) {
				continue
			}
			findings = append(findings, f)
		}
	}

	if cfg.ShellCheck.Enabled {
		scFindings, err := shellcheck.Run(doc.Root, path, cfg.ShellCheck.Path)
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %w", path, err)
		}
		for _, f := range scFindings {
			if !cfg.RuleEnabled(f.RuleID) {
				continue
			}
			f = cfg.ApplySeverity(f)
			if !cfg.AboveMinSeverity(f) {
				continue
			}
			if !keep(f) {
				continue
			}
			findings = append(findings, f)
		}
	}

	return finding.Dedupe(findings), unjustified, nil
}

// reportUnjustified prints every inline suppression that carries no reason and
// returns how many there were.
func reportUnjustified(sm suppress.Map, path string) int {
	entries := sm.Entries()
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Line != entries[j].Line {
			return entries[i].Line < entries[j].Line
		}
		return entries[i].RuleID < entries[j].RuleID
	})
	n := 0
	for _, e := range entries {
		if e.Reason != "" || e.Line <= parser.ContextLine/2 {
			continue
		}
		n++
		fmt.Fprintf(os.Stderr, "%s:%d: %s is suppressed without a reason; add \"-- why\" to the glsec:ignore comment\n", output.Sanitize(path), e.Line, e.RuleID)
	}
	return n
}

// filterNewOnly keeps only findings absent from the baseline. baselinePath is
// empty for the default .glsec-ignore baseline (a missing default is treated as
// an empty baseline — everything is new); an explicit --baseline that cannot be
// read is an error. The number of baselined findings is reported to w.
func filterNewOnly(w io.Writer, findings []finding.Finding, baselinePath string) ([]finding.Finding, error) {
	path := baselinePath
	if path == "" {
		path = suppress.IgnoreFile
	}
	bl, err := baseline.Load(path)
	if err != nil {
		if baselinePath == "" && os.IsNotExist(err) {
			bl = baseline.Empty()
		} else {
			return nil, err
		}
	}

	newFindings := make([]finding.Finding, 0, len(findings))
	for _, f := range findings {
		if bl.IsNew(f) {
			newFindings = append(newFindings, f)
		}
	}
	if n := len(findings) - len(newFindings); n > 0 {
		_, _ = fmt.Fprintf(w, "%d finding(s) matched the baseline and were not reported\n", n)
	}
	return newFindings, nil
}

// ruleRan reports whether rule id ran in this scan: selected by --only,
// --skip and the config, inside the OWASP filter, and available for the
// GitLab version. ShellCheck findings (SCnnnn) run only when ShellCheck is on.
func ruleRan(cfg *config.Config, gitlabVersion gitlabver.Version, id string) bool {
	if !cfg.RuleEnabled(id) {
		return false
	}
	if strings.HasPrefix(id, "SC") {
		return cfg.ShellCheck.Enabled
	}
	return cfg.OWASPEnabled(rules.OWASPCategories(id)) && rules.EnabledFor(id, gitlabVersion)
}

// writeIgnoreFile writes the findings to .glsec-ignore as a baseline. An
// existing entry is replaced only when this run could have reported it: its
// file was scanned and its rule ran. Entries for other files or for rules
// left out with --only, --skip or the config are kept, as are comments, and
// a finding that already had an entry keeps that line, with its exp: date
// (#902). It returns the number of entries written for findings and kept.
func writeIgnoreFile(path string, findings []finding.Finding, scanned map[string]bool, ruleDidRun func(string) bool) (written, kept int, err error) {
	old, err := os.ReadFile(path) //nolint:gosec // G304: the fixed name .glsec-ignore in the working directory
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return 0, 0, err
	}
	lines := []string{ignoreFileHeader}
	previous := map[string]string{} // "file:line rule" -> its line
	for _, line := range strings.Split(strings.ReplaceAll(string(old), "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed == ignoreFileHeader {
			continue
		}
		fields := strings.Fields(trimmed)
		colon := strings.LastIndex(fields[0], ":")
		if strings.HasPrefix(trimmed, "#") || len(fields) < 2 || colon < 0 {
			lines = append(lines, line) // a comment or a line glsec can't read: not ours to drop
			continue
		}
		if scanned[fields[0][:colon]] && ruleDidRun(fields[1]) {
			previous[fields[0]+" "+fields[1]] = trimmed
			continue
		}
		lines = append(lines, trimmed)
		kept++
	}
	done := map[string]bool{}
	for _, f := range findings {
		key := fmt.Sprintf("%s:%d %s", f.File, f.Line, f.RuleID)
		if done[key] {
			continue
		}
		done[key] = true
		line := key
		if p, ok := previous[key]; ok {
			line = p
		}
		lines = append(lines, line)
		written++
	}
	content := strings.Join(lines, "\n") + "\n"
	return written, kept, os.WriteFile(path, []byte(content), 0600) //nolint:gosec
}

const ignoreFileHeader = "# Generated by glsec --generate-ignore"
