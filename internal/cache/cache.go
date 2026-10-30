// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/glsec/glsec/internal/finding"
)

// Entry is a cached scan result.
type Entry struct {
	Findings   []finding.Finding    `json:"findings"`
	Suppressed []finding.Suppressed `json:"suppressed,omitempty"`
	JobCount   int                  `json:"job_count"`
	CachedAt   time.Time            `json:"cached_at"`
}

// Dir returns the glsec cache directory, respecting XDG_CACHE_HOME.
func Dir() string {
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		base = filepath.Join(home, ".cache")
	}
	return filepath.Join(base, "glsec")
}

// Key computes a deterministic hex key from all inputs that affect scan results.
// filePaths must include the main pipeline file and all discovered child pipeline files.
// configPath and ignorePath are read from disk if they exist.
//
// day is the current date as YYYY-MM-DD. It is part of the key because
// suppressions can carry an expiry date: without it, a suppression that expired
// overnight would keep hiding its finding until some file happened to change.
// The cost is one cache miss per day.
func Key(version, day, gitlabVersion string, filePaths []string, configPath, ignorePath string, excludePatterns, only, skip []string) (string, error) {
	h := sha256.New()

	_, _ = fmt.Fprintf(h, "version:%s\n", version)
	_, _ = fmt.Fprintf(h, "day:%s\n", day)
	_, _ = fmt.Fprintf(h, "gitlab-version:%s\n", gitlabVersion)

	sorted := make([]string, len(excludePatterns))
	copy(sorted, excludePatterns)
	sort.Strings(sorted)
	for _, p := range sorted {
		_, _ = fmt.Fprintf(h, "exclude:%s\n", p)
	}

	hashSorted(h, "only", only)
	hashSorted(h, "skip", skip)

	sortedFiles := make([]string, len(filePaths))
	copy(sortedFiles, filePaths)
	sort.Strings(sortedFiles)
	for _, path := range sortedFiles {
		if err := hashFile(h, path); err != nil {
			return "", err
		}
	}

	for _, path := range []string{configPath, ignorePath} {
		if path == "" {
			continue
		}
		if err := hashFile(h, path); err != nil && !os.IsNotExist(err) {
			return "", err
		}
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// hashSorted writes a sorted, labelled list into the cache key so order does
// not affect the result.
func hashSorted(h io.Writer, label string, items []string) {
	sorted := make([]string, len(items))
	copy(sorted, items)
	sort.Strings(sorted)
	for _, s := range sorted {
		_, _ = fmt.Fprintf(h, "%s:%s\n", label, s)
	}
}

func hashFile(h io.Writer, path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		if os.IsNotExist(err) {
			_, _ = fmt.Fprintf(h, "file:%s:missing\n", path)
			return nil
		}
		return err
	}
	data, err := os.ReadFile(resolved) //nolint:gosec
	if err != nil {
		if os.IsNotExist(err) {
			_, _ = fmt.Fprintf(h, "file:%s:missing\n", path)
			return nil
		}
		return err
	}
	fh := sha256.Sum256(data)
	_, _ = fmt.Fprintf(h, "file:%s:%s\n", path, hex.EncodeToString(fh[:]))
	return nil
}

// usableDir reports whether dir is a directory that only the current user can
// write to. A cache entry decides what glsec reports, so one that someone else
// could plant or replace must not be read.
func usableDir(dir string) bool {
	fi, err := os.Stat(dir)
	return err == nil && fi.IsDir() && ownedByCurrentUser(fi)
}

// Load reads a cached entry by key. Returns nil, false on miss or error.
// Only a regular file counts as an entry, not a symbolic link to one.
func Load(key string) (*Entry, bool) {
	dir := Dir()
	if dir == "" || !usableDir(dir) {
		return nil, false
	}
	path := filepath.Join(dir, key+".json")
	if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() {
		return nil, false
	}
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, false
	}
	var entry Entry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, false
	}
	return &entry, true
}

// Store writes an entry to the cache. Silently ignores write errors.
// The entry is written to a temporary file and renamed into place, so a
// symbolic link planted under the entry's name is replaced, not written
// through.
func Store(key string, entry *Entry) {
	dir := Dir()
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0700); err != nil || !usableDir(dir) {
		return
	}
	entry.CachedAt = time.Now()
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(dir, key+".*.tmp")
	if err != nil {
		return
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmp.Name(), filepath.Join(dir, key+".json")) != nil {
		_ = os.Remove(tmp.Name())
	}
	sweep(dir, time.Now())
}

// staleAfter is the age at which sweep removes a file. An entry stored on an
// earlier day can't be hit again, since the day is part of the key, and a
// temporary file that old was left by a write that was interrupted.
const staleAfter = 24 * time.Hour

// sweep removes stale entries and temporary files from dir. Without it the
// cache would grow by one entry per pipeline and day, for good.
func sweep(dir string, now time.Time) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !isCacheFile(e.Name()) || !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil || now.Sub(info.ModTime()) < staleAfter {
			continue
		}
		_ = os.Remove(filepath.Join(dir, e.Name()))
	}
}

func isCacheFile(name string) bool {
	ext := filepath.Ext(name)
	return ext == ".json" || ext == ".tmp"
}

// Clear removes all cached entries and temporary files. It lists the directory instead of
// globbing it: a cache path with glob characters such as [ ] would otherwise
// be read as a pattern and match nothing (#734).
func Clear() error {
	dir := Dir()
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if !isCacheFile(e.Name()) {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
