// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package color

import (
	"bytes"
	"os"
	"runtime"
	"testing"
)

// nonTTYWriter ensures IsEnabled hits the "w is not *os.File" branch
// without needing real TTY detection.
type nonTTYWriter struct{ bytes.Buffer }

func TestIsEnabled_NoColorWins(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	t.Setenv("FORCE_COLOR", "1")
	if IsEnabled(false, os.Stdout) {
		t.Error("NO_COLOR must take precedence over FORCE_COLOR")
	}
	if IsEnabled(true, os.Stdout) {
		t.Error("--no-color must take precedence")
	}
}

func TestIsEnabled_ForceColor(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	for _, env := range []string{"FORCE_COLOR", "CLICOLOR_FORCE"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv("FORCE_COLOR", "")
			t.Setenv("CLICOLOR_FORCE", "")
			t.Setenv(env, "1")
			if !IsEnabled(false, &nonTTYWriter{}) {
				t.Errorf("%s=1 should enable color even for non-TTY writer", env)
			}
		})
	}
}

func TestIsEnabled_ForceColorZero(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("CLICOLOR_FORCE", "")
	t.Setenv("FORCE_COLOR", "0")
	if IsEnabled(false, &nonTTYWriter{}) {
		t.Error("FORCE_COLOR=0 should NOT enable color (treated as off)")
	}
}

func TestIsEnabled_NonTTYDefault(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("FORCE_COLOR", "")
	t.Setenv("CLICOLOR_FORCE", "")
	if IsEnabled(false, &nonTTYWriter{}) {
		t.Error("non-TTY writer with no env should be disabled")
	}
}

func TestIsEnabled_NoColorBeatsClicolorForce(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	t.Setenv("FORCE_COLOR", "")
	t.Setenv("CLICOLOR_FORCE", "1")
	if IsEnabled(false, &nonTTYWriter{}) {
		t.Error("NO_COLOR must take precedence over CLICOLOR_FORCE")
	}
}

func TestIsTerminal_NotAFile(t *testing.T) {
	if IsTerminal(&nonTTYWriter{}) {
		t.Error("a writer that is not an *os.File must not be a terminal")
	}
}

func TestIsTerminal_RegularFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "color")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer func() { _ = f.Close() }()
	if IsTerminal(f) {
		t.Error("a regular file must not be a terminal")
	}
}

func TestIsTerminal_CharacterDevice(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no character device to open on Windows")
	}
	f, err := os.Open("/dev/null")
	if err != nil {
		t.Skipf("cannot open a character device: %v", err)
	}
	defer func() { _ = f.Close() }()
	if !IsTerminal(f) {
		t.Error("a character device must be a terminal")
	}
}

func TestIsTerminal_StatFails(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "color")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	_ = f.Close()
	if IsTerminal(f) {
		t.Error("a file that cannot be stat'ed must not be a terminal")
	}
}

func TestColors(t *testing.T) {
	tests := []struct {
		name  string
		color func(string, bool) string
		code  string
	}{
		{"red", Red, "\033[31m"},
		{"yellow", Yellow, "\033[33m"},
		{"bold", Bold, "\033[1m"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.color("text", false); got != "text" {
				t.Errorf("disabled: got %q, want %q", got, "text")
			}
			want := tt.code + "text" + "\033[0m"
			if got := tt.color("text", true); got != want {
				t.Errorf("enabled: got %q, want %q", got, want)
			}
		})
	}
}
