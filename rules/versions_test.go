package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/version"
)

func TestEnabledFor(t *testing.T) {
	cases := []struct {
		id   string
		v    version.Version
		want bool
	}{
		// zero version always passes
		{"GL009", version.Version{}, true},
		// GL009 requires 15.7
		{"GL009", version.Version{Major: 15, Minor: 7}, true},
		{"GL009", version.Version{Major: 15, Minor: 6}, false},
		{"GL009", version.Version{Major: 16, Minor: 0}, true},
		// GL001 has no version gate
		{"GL001", version.Version{Major: 15, Minor: 0}, true},
		{"GL001", version.Version{Major: 1, Minor: 0}, true},
	}
	for _, tc := range cases {
		got := EnabledFor(tc.id, tc.v)
		if got != tc.want {
			t.Errorf("EnabledFor(%q, %s) = %v, want %v", tc.id, tc.v, got, tc.want)
		}
	}
}
