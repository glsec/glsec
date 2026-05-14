package rules

import "github.com/glsec/glsec/internal/version"

// minVersions maps rule IDs to the minimum GitLab version that introduced
// the feature the rule checks. Rules not listed here have no version gate.
var minVersions = map[string]version.Version{
	"GL009": {Major: 15, Minor: 7}, // id_tokens:
	"GL010": {Major: 14, Minor: 9}, // trigger: forward:
	"GL014": {Major: 12, Minor: 9}, // artifacts: reports: dotenv:
}

// EnabledFor returns true if rule id should run against the given GitLab
// version. A zero version (unset) always returns true.
func EnabledFor(id string, v version.Version) bool {
	if v.IsZero() {
		return true
	}
	min, ok := minVersions[id]
	if !ok {
		return true
	}
	return v.AtLeast(min)
}
