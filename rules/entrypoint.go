// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"path"
	"strings"

	"github.com/glsec/glsec/internal/parser"
	"gopkg.in/yaml.v3"
)

// containerScripts returns the shell scripts in the image: and services: of a
// job, default: or top-level mapping: the element after -c in an entrypoint:
// or command: array that calls a shell. Both run in a container that gets the
// job's CI/CD variables, so they are code the pipeline runs (#1160).
func containerScripts(container *yaml.Node) []*yaml.Node {
	var scripts []*yaml.Node
	if image := parser.FindKey(container, "image"); image != nil {
		scripts = appendExecScript(scripts, parser.FindKey(image, "entrypoint"))
	}
	services := parser.FindKey(container, "services")
	if services == nil || services.Kind != yaml.SequenceNode || parser.IsReference(services) {
		return scripts
	}
	for _, service := range services.Content {
		scripts = appendExecScript(scripts, parser.FindKey(service, "entrypoint"))
		scripts = appendExecScript(scripts, parser.FindKey(service, "command"))
	}
	return scripts
}

func appendExecScript(scripts []*yaml.Node, array *yaml.Node) []*yaml.Node {
	if script := shellCScript(array); script != nil {
		return append(scripts, script)
	}
	return scripts
}

// shellCScript returns the script of an exec array that runs a POSIX shell
// with -c, as in ["/bin/sh", "-c", "…"], ["bash", "-ec", "…"] or
// ["/usr/bin/env", "bash", "-c", "…"]. Any other array gives nil, such as
// ["postgres", "-c", "max_connections=200"].
func shellCScript(array *yaml.Node) *yaml.Node {
	if array == nil || array.Kind != yaml.SequenceNode || parser.IsReference(array) {
		return nil
	}
	items := array.Content
	if len(items) == 0 || items[0].Kind != yaml.ScalarNode {
		return nil
	}
	var shell string
	first, rest := strings.Fields(items[0].Value), items[1:]
	switch {
	case len(first) == 2 && path.Base(first[0]) == "env":
		shell = first[1]
	case len(first) == 1 && path.Base(first[0]) == "env" && len(rest) > 0:
		shell, rest = rest[0].Value, rest[1:]
	case len(first) == 1:
		shell = first[0]
	}
	if !posixShells[path.Base(shell)] {
		return nil
	}
	var args []string
	for _, item := range rest {
		if item.Kind != yaml.ScalarNode {
			break
		}
		args = append(args, item.Value)
	}
	if i := shellCArg(args); i >= 0 {
		return rest[i]
	}
	return nil
}

// shellCArg returns the index in a shell's arguments of the script after -c,
// or -1 without one.
func shellCArg(args []string) int {
	sawC := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-o" || a == "+o":
			i++ // its argument is the option's name
		case strings.HasPrefix(a, "--"):
		case strings.HasPrefix(a, "-") || strings.HasPrefix(a, "+"):
			sawC = sawC || strings.HasPrefix(a, "-") && strings.Contains(a, "c")
		case sawC:
			return i
		default:
			return -1 // a script file
		}
	}
	return -1
}
