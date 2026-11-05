// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

// Command patchcoverage checks how much of the code a pull request adds or
// changes the tests cover (#1229). It reads a Go coverage profile and a
// unified diff. A changed line counts when it has statements, so comments,
// blank lines and test files don't. Exit 1 means below the minimum, exit 2 that
// the check couldn't run.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// block is a statement block of a coverage profile.
type block struct {
	start, end int
	covered    bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("patchcoverage", flag.ContinueOnError)
	flags.SetOutput(stderr)
	profilePath := flags.String("profile", "coverage.out", "Go coverage profile")
	diffPath := flags.String("diff", "", "unified diff of the change, made with --unified=0")
	module := flags.String("module", "github.com/glsec/glsec", "module path to strip from the profile's file names")
	minimum := flags.Float64("min", 80, "minimum coverage of changed lines, in percent")
	grace := flags.Int("grace", 3, "this many uncovered lines always pass, so one error path doesn't fail a small change")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	blocks, err := readFile(*profilePath, func(r io.Reader) (map[string][]block, error) { return parseProfile(r, *module) })
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "patchcoverage:", err)
		return 2
	}
	changed, err := readFile(*diffPath, parseDiff)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "patchcoverage:", err)
		return 2
	}
	r := check(blocks, changed)
	return r.write(stdout, *minimum, *grace)
}

func readFile[T any](path string, parse func(io.Reader) (T, error)) (T, error) {
	var zero T
	f, err := os.Open(path) //nolint:gosec // G304: a path CI passes on the command line
	if err != nil {
		return zero, err
	}
	defer func() { _ = f.Close() }()
	return parse(f)
}

// profileLineRe matches a profile line: file:start.col,end.col statements count.
var profileLineRe = regexp.MustCompile(`^(.+):(\d+)\.\d+,(\d+)\.\d+ \d+ (\d+)$`)

func parseProfile(r io.Reader, module string) (map[string][]block, error) {
	blocks := map[string][]block{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "mode:") || line == "" {
			continue
		}
		m := profileLineRe.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("profile line %q", line)
		}
		start, _ := strconv.Atoi(m[2])
		end, _ := strconv.Atoi(m[3])
		file := strings.TrimPrefix(strings.TrimPrefix(m[1], module), "/")
		blocks[file] = append(blocks[file], block{start, end, m[4] != "0"})
	}
	return blocks, scanner.Err()
}

// hunkRe matches a diff hunk header; group 1 and 2 are the new file's range.
var hunkRe = regexp.MustCompile(`^@@ -\S+ \+(\d+)(?:,(\d+))? @@`)

// parseDiff returns the changed lines of each file in the new version.
func parseDiff(r io.Reader) (map[string][]int, error) {
	changed := map[string][]int{}
	file := ""
	scanner := bufio.NewScanner(r)
	scanner.Buffer(nil, 16<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if name, ok := strings.CutPrefix(line, "+++ "); ok {
			file = strings.TrimPrefix(name, "b/")
			continue
		}
		m := hunkRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		start, _ := strconv.Atoi(m[1])
		count := 1
		if m[2] != "" {
			count, _ = strconv.Atoi(m[2])
		}
		for l := start; l < start+count; l++ {
			changed[file] = append(changed[file], l)
		}
	}
	return changed, scanner.Err()
}

// result is what the changed lines come to.
type result struct {
	covered   int
	uncovered []string
}

func check(blocks map[string][]block, changed map[string][]int) result {
	var r result
	files := make([]string, 0, len(changed))
	for file := range changed {
		files = append(files, file)
	}
	slices.Sort(files)
	for _, file := range files {
		for _, line := range changed[file] {
			executable, covered := false, false
			for _, b := range blocks[file] {
				if b.start <= line && line <= b.end {
					executable = true
					covered = covered || b.covered
				}
			}
			switch {
			case covered:
				r.covered++
			case executable:
				r.uncovered = append(r.uncovered, fmt.Sprintf("%s:%d", file, line))
			}
		}
	}
	return r
}

// write reports the result and returns the exit code.
func (r result) write(w io.Writer, minimum float64, grace int) int {
	total := r.covered + len(r.uncovered)
	if total == 0 {
		_, _ = fmt.Fprintln(w, "patch coverage: no changed statements")
		return 0
	}
	percent := 100 * float64(r.covered) / float64(total)
	_, _ = fmt.Fprintf(w, "patch coverage %.1f%% (%d/%d changed lines, minimum %.0f%%)\n", percent, r.covered, total, minimum)
	for _, line := range r.uncovered {
		_, _ = fmt.Fprintln(w, "not covered:", line)
	}
	if percent < minimum && len(r.uncovered) > grace {
		return 1
	}
	return 0
}
