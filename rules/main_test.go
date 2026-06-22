package rules

import (
	"os"
	"testing"
)

// TestMain configures the config-gated global singletons (GL065, GL075) with an
// allowlist so their fixtures fire in TestRuleConsistency. These rules are a
// no-op without an allowlist, and the consistency check exercises the global
// singletons. Unit tests use their own local instances and are unaffected.
func TestMain(m *testing.M) {
	GL065.SetAllowedRegistries([]string{"registry.example.com", "ghcr.io/myorg"})
	GL075.SetAllowedIncludeSources([]string{"my-group", "gitlab.com/trusted-components"})
	os.Exit(m.Run())
}
