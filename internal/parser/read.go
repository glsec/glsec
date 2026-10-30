// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
)

// MaxFileSize is the largest pipeline file glsec reads (#894). Real pipelines
// are kilobytes; a 16 MB file with 400,000 script lines still scans in under a
// minute, so the limit only stops input such as /dev/zero.
var MaxFileSize int64 = 64 << 20

// StdinName is the file name of a pipeline read from stdin without
// --stdin-filename (#833).
const StdinName = "<stdin>"

// ErrNotRegular is the error for a FIFO, device, socket or directory.
var ErrNotRegular = errors.New("not a regular file")

// ReadFile reads a pipeline file. It refuses anything but a regular file, so a
// FIFO can't block the scan and a device can't be read without end, and a
// file larger than MaxFileSize, also when it grows while it is read.
func ReadFile(path string) ([]byte, error) {
	// Stat before opening: opening a FIFO blocks until a writer appears.
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if err := checkFile(path, fi); err != nil {
		return nil, err
	}
	f, err := os.Open(path) //nolint:gosec // G304: intentional, reads user-supplied files
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	// The file may have been replaced between Stat and Open.
	if fi, err = f.Stat(); err != nil {
		return nil, err
	}
	if err := checkFile(path, fi); err != nil {
		return nil, err
	}
	return ReadAll(f, path)
}

// ReadAll reads r, a pipeline file or stdin, up to MaxFileSize; name is the
// file name in the error.
func ReadAll(r io.Reader, name string) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > MaxFileSize {
		return nil, tooLarge(name, int64(len(data)))
	}
	return data, nil
}

// The errors are *fs.PathError like the ones from os, so they name the file
// once: "read ci.yml: not a regular file".
func checkFile(path string, fi os.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return &fs.PathError{Op: "read", Path: path, Err: ErrNotRegular}
	}
	if fi.Size() > MaxFileSize {
		return tooLarge(path, fi.Size())
	}
	return nil
}

func tooLarge(path string, size int64) error {
	return &fs.PathError{Op: "read", Path: path, Err: fmt.Errorf("%s, larger than the %s limit", megabytes(size), megabytes(MaxFileSize))}
}

func megabytes(n int64) string {
	if n%(1<<20) == 0 {
		return fmt.Sprintf("%d MB", n>>20)
	}
	return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
}
