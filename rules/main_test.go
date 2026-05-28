package rules

import (
	"os"
	"testing"
)

// TestMain configures the global GL065 singleton with an allowlist so its
// fixture fires in TestRuleConsistency. GL065 is config-gated (a no-op without
// an allowlist), and the consistency check exercises the global singleton.
// Unit tests use their own local gl065 instances and are unaffected.
func TestMain(m *testing.M) {
	GL065.SetAllowedRegistries([]string{"registry.example.com", "ghcr.io/myorg"})
	os.Exit(m.Run())
}
