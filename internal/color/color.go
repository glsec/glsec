package color

import (
	"io"
	"os"
)

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	red    = "\033[31m"
	yellow = "\033[33m"
)

// IsEnabled returns true if color output should be used.
// Color is disabled when:
//   - noColor is true (--no-color flag)
//   - NO_COLOR env var is set (https://no-color.org)
//   - w is not a terminal
func IsEnabled(noColor bool, w io.Writer) bool {
	if noColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// Red wraps s in red ANSI codes if enabled.
func Red(s string, enabled bool) string {
	if !enabled {
		return s
	}
	return red + s + reset
}

// Yellow wraps s in yellow ANSI codes if enabled.
func Yellow(s string, enabled bool) string {
	if !enabled {
		return s
	}
	return yellow + s + reset
}

// Bold wraps s in bold ANSI codes if enabled.
func Bold(s string, enabled bool) string {
	if !enabled {
		return s
	}
	return bold + s + reset
}
