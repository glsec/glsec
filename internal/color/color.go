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
//
// Precedence (highest first):
//  1. noColor (--no-color flag) or NO_COLOR env → disabled
//  2. FORCE_COLOR or CLICOLOR_FORCE env set to a non-empty, non-"0" value → enabled
//  3. Auto-detect: w must be a terminal
func IsEnabled(noColor bool, w io.Writer) bool {
	if noColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	if forceColor("FORCE_COLOR") || forceColor("CLICOLOR_FORCE") {
		return true
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

func forceColor(env string) bool {
	v := os.Getenv(env)
	return v != "" && v != "0"
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
