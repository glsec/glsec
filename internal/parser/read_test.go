// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

// mkfifo creates a FIFO with the mkfifo program; syscall.Mkfifo doesn't
// exist on Windows, which has no FIFOs in the file system.
func mkfifo(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("no FIFOs on Windows")
	}
	if out, err := exec.Command("mkfifo", path).CombinedOutput(); err != nil { //nolint:gosec // G204: a test path in a temporary directory
		t.Skipf("mkfifo: %v %s", err, out)
	}
}

// readWithin fails the test instead of hanging when ReadFile blocks.
func readWithin(t *testing.T, path string) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := ReadFile(path)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatalf("ReadFile(%s) blocked", path)
		return nil
	}
}

func TestReadFile_NotARegularFile(t *testing.T) {
	dir := t.TempDir()
	if err := readWithin(t, dir); !errors.Is(err, ErrNotRegular) {
		t.Errorf("directory: err = %v, want ErrNotRegular", err)
	}
	if runtime.GOOS != "windows" {
		if err := readWithin(t, "/dev/zero"); !errors.Is(err, ErrNotRegular) {
			t.Errorf("/dev/zero: err = %v, want ErrNotRegular", err)
		}
	}
	fifo := filepath.Join(dir, "child.yml")
	mkfifo(t, fifo)
	err := readWithin(t, fifo)
	if !errors.Is(err, ErrNotRegular) {
		t.Fatalf("FIFO: err = %v, want ErrNotRegular", err)
	}
	if want := "read " + fifo + ": not a regular file"; err.Error() != want {
		t.Errorf("message = %q, want %q", err, want)
	}
}

func TestReadFile_SizeLimit(t *testing.T) {
	old := MaxFileSize
	MaxFileSize = 2 << 20
	t.Cleanup(func() { MaxFileSize = old })

	dir := t.TempDir()
	big := filepath.Join(dir, "big.yml")
	if err := os.WriteFile(big, make([]byte, 3<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := ReadFile(big)
	if err == nil || !strings.HasSuffix(err.Error(), ": 3 MB, larger than the 2 MB limit") {
		t.Errorf("err = %v, want the size and the limit", err)
	}

	exact := filepath.Join(dir, "exact.yml")
	if err := os.WriteFile(exact, make([]byte, 2<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadFile(exact); err != nil || len(data) != 2<<20 {
		t.Errorf("a file of exactly the limit: %d bytes, err %v", len(data), err)
	}
}

func TestReadAll(t *testing.T) {
	old := MaxFileSize
	MaxFileSize = 4
	t.Cleanup(func() { MaxFileSize = old })

	if data, err := ReadAll(strings.NewReader("a: 1"), StdinName); err != nil || string(data) != "a: 1" {
		t.Errorf("input of exactly the limit: %q, err %v", data, err)
	}
	if _, err := ReadAll(strings.NewReader("a: 12"), StdinName); err == nil || !strings.Contains(err.Error(), "read <stdin>:") {
		t.Errorf("err = %v, want the limit error naming <stdin>", err)
	}
	broken := errors.New("broken pipe")
	if _, err := ReadAll(iotest.ErrReader(broken), StdinName); !errors.Is(err, broken) {
		t.Errorf("err = %v, want the reader's error", err)
	}
}

func TestReadFile_Missing(t *testing.T) {
	if _, err := ReadFile(filepath.Join(t.TempDir(), "missing.yml")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v, want ErrNotExist", err)
	}
}

func TestMegabytes(t *testing.T) {
	for n, want := range map[int64]string{64 << 20: "64 MB", 3<<20 + 1<<19: "3.5 MB"} {
		if got := megabytes(n); got != want {
			t.Errorf("megabytes(%d) = %q, want %q", n, got, want)
		}
	}
}
