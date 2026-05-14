package version

import (
	"fmt"
	"strconv"
	"strings"
)

// Version represents a GitLab major.minor version.
// The zero value means "unset / latest" — no version gating.
type Version struct {
	Major int
	Minor int
}

// Minimum is the lowest GitLab version glsec officially supports.
var Minimum = Version{Major: 15, Minor: 0}

// IsZero returns true for the zero value (unset / latest).
func (v Version) IsZero() bool { return v.Major == 0 && v.Minor == 0 }

// AtLeast returns true if v is greater than or equal to other.
func (v Version) AtLeast(other Version) bool {
	if v.Major != other.Major {
		return v.Major > other.Major
	}
	return v.Minor >= other.Minor
}

// String returns "MAJOR.MINOR".
func (v Version) String() string {
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

// Parse parses a version string like "16.0", "15.7", or "16" (minor defaults to 0).
func Parse(s string) (Version, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Version{}, nil
	}
	parts := strings.SplitN(s, ".", 2)
	major, err := strconv.Atoi(parts[0])
	if err != nil || major < 1 {
		return Version{}, fmt.Errorf("invalid GitLab version %q: major must be a positive integer", s)
	}
	minor := 0
	if len(parts) == 2 {
		minor, err = strconv.Atoi(parts[1])
		if err != nil || minor < 0 {
			return Version{}, fmt.Errorf("invalid GitLab version %q: minor must be a non-negative integer", s)
		}
	}
	return Version{Major: major, Minor: minor}, nil
}
