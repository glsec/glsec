package rules

// ASVSVersion is the OWASP ASVS release the V14 (Build and Deploy) mappings
// below are pinned to. Bump only after reviewing the mapping against the new
// release.
const ASVSVersion = "4.0.3"

// asvsRequirements maps a rule ID to the OWASP ASVS v4.0.3 V14 requirement(s)
// it provides evidence for.
var asvsRequirements = map[string][]string{
	"GL001": {"ASVS-V14.2.2"},
	"GL003": {"ASVS-V14.2.1", "ASVS-V14.3.1"},
	"GL006": {"ASVS-V14.3.3"},
	"GL007": {"ASVS-V14.3.4"},
	"GL008": {"ASVS-V14.3.2"},
	"GL011": {"ASVS-V14.2.1"},
	"GL014": {"ASVS-V14.3.3"},
	"GL015": {"ASVS-V14.3.4"},
	"GL016": {"ASVS-V14.2.1"},
	"GL018": {"ASVS-V14.3.3"},
	"GL019": {"ASVS-V14.3.1"},
	"GL020": {"ASVS-V14.2.3"},
	"GL021": {"ASVS-V14.3.3"},
	"GL022": {"ASVS-V14.2.2"},
	"GL023": {"ASVS-V14.2.2"},
	"GL025": {"ASVS-V14.3.4"},
	"GL026": {"ASVS-V14.2.2"},
	"GL027": {"ASVS-V14.3.3"},
	"GL032": {"ASVS-V14.3.3"},
	"GL033": {"ASVS-V14.3.3"},
	"GL035": {"ASVS-V14.3.3"},
	"GL036": {"ASVS-V14.3.3"},
	"GL038": {"ASVS-V14.3.3"},
	"GL039": {"ASVS-V14.3.2"},
	"GL041": {"ASVS-V14.2.2", "ASVS-V14.4.1"},
}

// asvsRequirementNames maps an ASVS requirement ID to its short description.
var asvsRequirementNames = map[string]string{
	"ASVS-V14.2.1": "Verify that all components come from trusted, continually maintained sources",
	"ASVS-V14.2.2": "Verify that all components are up to date and pinned to a specific version",
	"ASVS-V14.2.3": "Verify that third-party dependencies are verified for integrity",
	"ASVS-V14.3.1": "Verify that build pipeline configuration is protected from unauthorized modification",
	"ASVS-V14.3.2": "Verify that security tooling runs in the pipeline and failures block the build",
	"ASVS-V14.3.3": "Verify that secrets are not present in source code or pipeline logs",
	"ASVS-V14.3.4": "Verify that the build environment is isolated",
	"ASVS-V14.4.1": "Verify that dependence on third-party CI/CD services is minimised",
}

// ASVSRequirements returns the ASVS V14 requirement IDs mapped to rule id, or
// nil if the rule has no ASVS mapping.
func ASVSRequirements(id string) []string { return asvsRequirements[id] }

// ASVSRequirementName returns the human-readable description for an ASVS
// requirement ID.
func ASVSRequirementName(reqID string) string { return asvsRequirementNames[reqID] }
