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

type gl015 struct{}

var GL015 = &gl015{}

func (r *gl015) ID() string { return "GL015" }

var (
	// dockerCmdRe matches docker or podman build/push/tag/buildx commands.
	dockerCmdRe = regexp.MustCompile(`\b(?:docker|podman)\s+(?:build|push|tag|buildx)\b`)

	// userControlledTagRe matches an image tag that uses a user-controlled variable,
	// i.e. a colon (tag separator) followed by a user-controlled predefined variable.
	// CI_COMMIT_SHA, CI_PIPELINE_ID, and CI_COMMIT_SHORT_SHA are safe — not listed here.
	userControlledTagRe = regexp.MustCompile(
		`:\$\{?(CI_COMMIT_REF_NAME|CI_COMMIT_REF_SLUG|CI_COMMIT_BRANCH|CI_MERGE_REQUEST_SOURCE_BRANCH_NAME)\}?`,
	)
)

func (r *gl015) Check(doc *yaml.Node, file string) []finding.Finding {
	var findings []finding.Finding
	EachScriptLine(doc, file, func(item *yaml.Node, file, job string) {
		if !dockerCmdRe.MatchString(item.Value) {
			return
		}
		for _, cmd := range shellCommands(item.Value) {
			varName := ""
			for _, t := range writtenImageRefs(withoutSudo(commandWords(cmd.text))) {
				// The name from the group: ${NAME//x/y} or ${NAME:-d} has no } right after it (#977).
				if m := userControlledTagRe.FindStringSubmatch(t); m != nil {
					varName = m[1]
					break
				}
			}
			if varName == "" {
				continue
			}
			f := finding.Finding{
				RuleID:   "GL015",
				Severity: finding.Warn,
				Job:      job,
				Message: fmt.Sprintf(
					"Docker image tag uses user-controlled variable $%s — a branch named \"latest\" or \"main\" overwrites the production tag; use $CI_COMMIT_SHA instead",
					varName,
				),
				File: file,
				Line: parser.ScalarContentLine(item, cmd.line),
			}
			if cmd.line == 0 {
				f.Col = item.Column
			}
			findings = append(findings, f)
		}
	})
	return findings
}

// writtenImageRefs returns the image references a docker/podman command
// writes: the -t/--tag values of build, the target of tag, the image of push.
// The source of `docker tag` and values such as --label are only read.
func writtenImageRefs(words []string) []string {
	if name := commandName(words); name != "docker" && name != "podman" || len(words) < 2 {
		return nil
	}
	args := words[1:]
	if args[0] == "buildx" || args[0] == "image" {
		args = args[1:]
	}
	if len(args) > 1 && args[0] == "imagetools" && args[1] == "create" {
		args = append([]string{"build"}, args[2:]...) // writes its -t tags like build
	}
	if len(args) == 0 {
		return nil
	}
	sub, args := args[0], args[1:]
	var positional, tags []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-t" || a == "--tag":
			if i+1 < len(args) {
				tags = append(tags, args[i+1])
				i++
			}
		case strings.HasPrefix(a, "--tag="):
			tags = append(tags, strings.TrimPrefix(a, "--tag="))
		case strings.HasPrefix(a, "-t") && len(a) > 2 && !strings.HasPrefix(a, "--"):
			tags = append(tags, a[2:])
		case strings.HasPrefix(a, "-"):
		default:
			positional = append(positional, a)
		}
	}
	switch sub {
	case "build":
		return tags
	case "tag":
		if len(positional) > 0 {
			return positional[len(positional)-1:]
		}
	case "push":
		return positional
	}
	return nil
}
