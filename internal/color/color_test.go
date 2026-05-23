package color

import (
	"bytes"
	"os"
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
