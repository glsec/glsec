// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/glsec/glsec/internal/finding"
)

const hammerKey = "shared"

// hammer stores and loads one key rounds times. Every hit must be a whole
// entry as some writer stored it, never a mix or a truncated one; a miss is
// fine, since on Windows a rename onto a file another process has open fails
// and Store gives up.
func hammer(writer, rounds int) error {
	for i := range rounds {
		n := writer*rounds + i
		Store(hammerKey, &Entry{
			JobCount: n,
			Findings: []finding.Finding{{RuleID: "GL001", Message: fmt.Sprintf("entry %d", n)}},
		})
		got, ok := Load(hammerKey)
		if !ok {
			continue
		}
		if len(got.Findings) != 1 || got.Findings[0].Message != fmt.Sprintf("entry %d", got.JobCount) {
			return fmt.Errorf("Load returned an entry no writer stored: %+v", got)
		}
	}
	return nil
}

func assertNoTempFiles(t *testing.T) {
	t.Helper()
	tmp, err := filepath.Glob(filepath.Join(Dir(), "*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tmp) != 0 {
		t.Errorf("temporary files left behind: %v", tmp)
	}
}

func TestStoreAndLoad_ConcurrentGoroutines(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for w := range 8 {
		wg.Go(func() { errs <- hammer(w, 50) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	assertNoTempFiles(t)
}

// TestHelperHammer is the child of TestStoreAndLoad_ConcurrentProcesses; it
// does nothing in a normal run.
func TestHelperHammer(t *testing.T) {
	if os.Getenv("GLSEC_CACHE_HAMMER") == "" {
		t.Skip("helper process")
	}
	var writer int
	if _, err := fmt.Sscan(os.Getenv("GLSEC_CACHE_HAMMER"), &writer); err != nil {
		t.Fatal(err)
	}
	if err := hammer(writer, 100); err != nil {
		t.Fatal(err)
	}
}

func TestStoreAndLoad_ConcurrentProcesses(t *testing.T) {
	if testing.Short() {
		t.Skip("starts child processes")
	}
	cacheHome := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cacheHome)

	cmds := make([]*exec.Cmd, 4)
	outs := make([][]byte, len(cmds))
	var wg sync.WaitGroup
	for i := range cmds {
		cmds[i] = exec.Command(os.Args[0], "-test.run=^TestHelperHammer$", "-test.count=1") //nolint:gosec
		cmds[i].Env = append(os.Environ(), fmt.Sprintf("GLSEC_CACHE_HAMMER=%d", i))
		wg.Go(func() {
			var err error
			outs[i], err = cmds[i].CombinedOutput()
			if err != nil {
				outs[i] = append(outs[i], []byte(err.Error())...)
			}
		})
	}
	wg.Wait()
	for i, cmd := range cmds {
		if !cmd.ProcessState.Success() {
			t.Errorf("writer %d failed:\n%s", i, outs[i])
		}
	}
	if _, ok := Load(hammerKey); !ok {
		t.Error("no entry left after all writers finished")
	}
	assertNoTempFiles(t)
}

func TestStore_RemovesStaleFiles(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	dir := Dir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * staleAfter)
	files := map[string]bool{ // name -> expected to survive
		"yesterday.json":      false,
		"key.123.tmp":         false,
		"key.456.tmp":         true, // fresh: a write still in progress
		"today.json":          true,
		"notes.txt":           true, // not a cache file
		"interrupted.old.tmp": false,
	}
	for name, keep := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if !keep || name == "notes.txt" {
			if err := os.Chtimes(path, old, old); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A stale directory with a cache file's name isn't a file to remove.
	sub := filepath.Join(dir, "dir.json")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(sub, old, old); err != nil {
		t.Fatal(err)
	}

	Store("k", &Entry{JobCount: 1})

	for name, keep := range files {
		_, err := os.Stat(filepath.Join(dir, name))
		if keep && err != nil {
			t.Errorf("%s was removed: %v", name, err)
		}
		if !keep && err == nil {
			t.Errorf("stale %s was kept", name)
		}
	}
	if _, err := os.Stat(sub); err != nil {
		t.Errorf("directory %s was removed: %v", sub, err)
	}
	if _, ok := Load("k"); !ok {
		t.Error("the new entry must be stored")
	}
}

func TestSweep_UnreadableDirIsANoOp(t *testing.T) {
	sweep(filepath.Join(t.TempDir(), "missing"), time.Now())
}

func TestClear_RemovesTempFiles(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	Store("k", &Entry{})
	tmp := filepath.Join(Dir(), "k.789.tmp")
	if err := os.WriteFile(tmp, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Clear(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tmp); err == nil {
		t.Error("Clear left a temporary file behind")
	}
}
