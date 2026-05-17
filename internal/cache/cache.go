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
	Findings []finding.Finding `json:"findings"`
	JobCount int               `json:"job_count"`
	CachedAt time.Time         `json:"cached_at"`
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
func Key(version, gitlabVersion string, filePaths []string, configPath, ignorePath string, excludePatterns []string) (string, error) {
	h := sha256.New()

	_, _ = fmt.Fprintf(h, "version:%s\n", version)
	_, _ = fmt.Fprintf(h, "gitlab-version:%s\n", gitlabVersion)

	sorted := make([]string, len(excludePatterns))
	copy(sorted, excludePatterns)
	sort.Strings(sorted)
	for _, p := range sorted {
		_, _ = fmt.Fprintf(h, "exclude:%s\n", p)
	}

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

// Load reads a cached entry by key. Returns nil, false on miss or error.
func Load(key string) (*Entry, bool) {
	dir := Dir()
	if dir == "" {
		return nil, false
	}
	data, err := os.ReadFile(filepath.Join(dir, key+".json")) //nolint:gosec
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
func Store(key string, entry *Entry) {
	dir := Dir()
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return
	}
	entry.CachedAt = time.Now()
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, key+".json"), data, 0600) //nolint:gosec
}

// Clear removes all cached entries.
func Clear() error {
	dir := Dir()
	if dir == "" {
		return nil
	}
	entries, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.Remove(e); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
