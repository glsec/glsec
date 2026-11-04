// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/glsec/glsec/internal/finding"
)

func TestStoreAndLoad(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())

	entry := &Entry{
		Findings: []finding.Finding{
			{RuleID: "GL001", Severity: finding.Error, File: "ci.yml", Line: 4, Message: "mutable tag"},
		},
		JobCount: 5,
	}

	Store("testkey", entry)

	got, ok := Load("testkey")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if len(got.Findings) != 1 || got.Findings[0].RuleID != "GL001" {
		t.Errorf("unexpected findings: %+v", got.Findings)
	}
	if got.JobCount != 5 {
		t.Errorf("expected JobCount=5, got %d", got.JobCount)
	}
}

func TestLoad_Miss(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	_, ok := Load("doesnotexist")
	if ok {
		t.Error("expected cache miss")
	}
}

func TestClear(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())

	Store("key1", &Entry{JobCount: 1})
	Store("key2", &Entry{JobCount: 2})

	if err := Clear(); err != nil {
		t.Fatal(err)
	}

	if _, ok := Load("key1"); ok {
		t.Error("expected key1 to be cleared")
	}
	if _, ok := Load("key2"); ok {
		t.Error("expected key2 to be cleared")
	}
}

func TestKey_Deterministic(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "ci.yml")
	if err := os.WriteFile(f, []byte("stages: [build]"), 0600); err != nil {
		t.Fatal(err)
	}

	k1, err := Key("v1.0.0", "2026-01-01", "16.0", []string{f}, "", "", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := Key("v1.0.0", "2026-01-01", "16.0", []string{f}, "", "", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if k1 != k2 {
		t.Errorf("key not deterministic: %q vs %q", k1, k2)
	}
}

func TestKey_DiffersOnContentChange(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "ci.yml")

	if err := os.WriteFile(f, []byte("stages: [build]"), 0600); err != nil {
		t.Fatal(err)
	}
	k1, err := Key("v1.0.0", "2026-01-01", "", []string{f}, "", "", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(f, []byte("stages: [deploy]"), 0600); err != nil {
		t.Fatal(err)
	}
	k2, err := Key("v1.0.0", "2026-01-01", "", []string{f}, "", "", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if k1 == k2 {
		t.Error("key should differ when file content changes")
	}
}

func TestKey_DiffersOnVersion(t *testing.T) {
	k1, _ := Key("v1.0.0", "2026-01-01", "", nil, "", "", nil, nil, nil)
	k2, _ := Key("v1.0.1", "2026-01-01", "", nil, "", "", nil, nil, nil)
	if k1 == k2 {
		t.Error("key should differ on version change")
	}
}

func TestKey_DiffersOnOnlySkip(t *testing.T) {
	base, _ := Key("v1.0.0", "2026-01-01", "", nil, "", "", nil, nil, nil)
	only, _ := Key("v1.0.0", "2026-01-01", "", nil, "", "", nil, []string{"GL001"}, nil)
	skip, _ := Key("v1.0.0", "2026-01-01", "", nil, "", "", nil, nil, []string{"GL001"})
	if base == only {
		t.Error("key should differ when --only is set")
	}
	if base == skip {
		t.Error("key should differ when --skip is set")
	}
	if only == skip {
		t.Error("--only and --skip with the same ID should produce different keys")
	}
}

func TestKeyChangesWithDay(t *testing.T) {
	day1, _ := Key("v1.0.0", "2026-01-01", "", nil, "", "", nil, nil, nil)
	day2, _ := Key("v1.0.0", "2026-01-02", "", nil, "", "", nil, nil, nil)
	if day1 == day2 {
		t.Error("the cache key must change between days, otherwise an expired suppression stays cached")
	}
}

func TestKey_ShellCheckBinaryMetadata(t *testing.T) {
	dir := t.TempDir()
	ci := filepath.Join(dir, "ci.yml")
	if err := os.WriteFile(ci, []byte("stages: [build]"), 0o600); err != nil {
		t.Fatal(err)
	}
	binA := filepath.Join(dir, "sc-a")
	binB := filepath.Join(dir, "sc-b")
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, p := range []string{binA, binB} {
		if err := os.WriteFile(p, []byte("stub"), 0o700); err != nil { //nolint:gosec // G306: executable stub in temp dir
			t.Fatal(err)
		}
		if err := os.Chtimes(p, t0, t0); err != nil {
			t.Fatal(err)
		}
	}

	disabled1, err := Key("v1.0.0", "2026-01-01", "", []string{ci}, "", "", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	disabled2, err := Key("v1.0.0", "2026-01-01", "", []string{ci}, "", "", nil, nil, nil, "")
	if err != nil || disabled1 != disabled2 {
		t.Fatalf("disabled shellcheck must keep its cache key: %q vs %q (err %v)", disabled1, disabled2, err)
	}

	kA, err := Key("v1.0.0", "2026-01-01", "", []string{ci}, "", "", nil, nil, nil, binA)
	if err != nil {
		t.Fatal(err)
	}
	kB, err := Key("v1.0.0", "2026-01-01", "", []string{ci}, "", "", nil, nil, nil, binB)
	if err != nil {
		t.Fatal(err)
	}
	if kA == disabled1 || kA == kB {
		t.Fatalf("keys must differ across disabled (%s), binA (%s), and binB (%s)", disabled1, kA, kB)
	}

	// Changing size at the exact same path and mtime invalidates the key.
	if err := os.WriteFile(binA, []byte("stub-larger"), 0o700); err != nil { //nolint:gosec // G306: executable stub in temp dir
		t.Fatal(err)
	}
	if err := os.Chtimes(binA, t0, t0); err != nil {
		t.Fatal(err)
	}
	kASize, err := Key("v1.0.0", "2026-01-01", "", []string{ci}, "", "", nil, nil, nil, binA)
	if err != nil || kASize == kA {
		t.Fatalf("key must change when binary size changes: %q vs %q (err %v)", kA, kASize, err)
	}

	// Changing mtime at the same path and size invalidates the key.
	t1 := t0.Add(2 * time.Second)
	if err := os.Chtimes(binA, t1, t1); err != nil {
		t.Fatal(err)
	}
	kAMtime, err := Key("v1.0.0", "2026-01-01", "", []string{ci}, "", "", nil, nil, nil, binA)
	if err != nil || kAMtime == kASize {
		t.Fatalf("key must change when binary mtime changes: %q vs %q (err %v)", kASize, kAMtime, err)
	}

	// Removing the binary returns an error so the caller gets no cache hit.
	if err := os.Remove(binA); err != nil {
		t.Fatal(err)
	}
	if _, err := Key("v1.0.0", "2026-01-01", "", []string{ci}, "", "", nil, nil, nil, binA); err == nil {
		t.Fatal("expected error when ShellCheck binary is missing")
	}
}
