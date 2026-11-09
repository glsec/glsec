// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/glsec/glsec/internal/parser"
)

// No rule changes a shared shellCommands result (#1325): after every rule ran
// over the fixtures, each cached entry still equals a fresh parse.
func TestCommandCacheUnchanged(t *testing.T) {
	var files []string
	if err := filepath.WalkDir("../testdata", func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && filepath.Ext(path) == ".yml" {
			files = append(files, path)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		src, err := os.ReadFile(f) //nolint:gosec // test reads its own fixtures
		if err != nil {
			t.Fatal(err)
		}
		doc, err := parser.Parse(src, ".gitlab-ci.yml")
		if err != nil {
			continue
		}
		for _, r := range All() {
			Check(r, doc, ".gitlab-ci.yml")
		}
	}
	// A fresh parse reads the cache for sh -c scripts, so compare a copy
	// without holding the lock.
	commandCache.Lock()
	entries := maps.Clone(commandCache.m)
	commandCache.Unlock()
	if len(entries) < 100 {
		t.Fatalf("only %d cached scripts after %d fixtures", len(entries), len(files))
	}
	for script, cached := range entries {
		if fresh := parseShellCommands(script); !reflect.DeepEqual(cached, fresh) && len(fresh)+len(cached) > 0 {
			t.Errorf("cached commands of %q changed:\n got  %+v\n want %+v", script, cached, fresh)
		}
	}
}

// An append to a shared result copies, so the cache keeps its entry.
func TestCommandCacheAppendCopies(t *testing.T) {
	a := shellCommands("echo a; echo b")
	_ = append(a, shellCommand{text: "injected"})
	b := shellCommands("echo a; echo b")
	if len(b) != 2 || b[1].text != "echo b" {
		t.Fatalf("cache changed by an append: %+v", b)
	}
}

// Here-document bodies are shifted to their item line without touching the
// cached parse of the same text.
func TestHeredocCommandsKeepsCache(t *testing.T) {
	body := "make build\nmake test\n"
	before := shellCommands(body)
	_ = heredocCommands(body, "EOF", 5)
	if after := shellCommands(body); !reflect.DeepEqual(before, after) || after[0].line != 0 {
		t.Fatalf("heredoc shift reached the cache: %+v", after)
	}
}
