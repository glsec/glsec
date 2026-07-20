package rules

// wholePipelineRules reason about a pipeline as a whole, so they cannot be
// evaluated against a CI/CD component template. A template is a fragment: the
// consuming pipeline supplies the surrounding configuration.
//
// Kept deliberately small. Rules that merely *read* a top-level key when it is
// present (GL043, GL074, GL080) degrade correctly on a fragment and stay
// enabled; only rules that fire on its absence belong here.
var wholePipelineRules = map[string]bool{
	// GL053 flags a missing top-level workflow: block. A component template
	// never has one, so it would fire on every template ever written.
	"GL053": true,
}

// AppliesToComponentTemplate reports whether a rule is meaningful when the file
// under analysis is a CI/CD component template rather than a full pipeline.
func AppliesToComponentTemplate(id string) bool {
	return !wholePipelineRules[id]
}
