package rules

// owaspCategories maps each rule ID to the OWASP CI/CD security categories it
// addresses. A rule may belong to more than one category.
var owaspCategories = map[string][]string{
	"GL001": {"CICD-SEC-3"},
	"GL002": {"CICD-SEC-6"},
	"GL003": {"CICD-SEC-3"},
	"GL004": {"CICD-SEC-6"},
	"GL005": {"CICD-SEC-7"},
	"GL006": {"CICD-SEC-6"},
	"GL007": {"CICD-SEC-7"},
	"GL008": {"CICD-SEC-1"},
	"GL009": {"CICD-SEC-5"},
	"GL010": {"CICD-SEC-6"},
	"GL011": {"CICD-SEC-9"},
	"GL012": {"CICD-SEC-1"},
	"GL013": {"CICD-SEC-1"},
	"GL014": {"CICD-SEC-6"},
	"GL015": {"CICD-SEC-3"},
	"GL016": {"CICD-SEC-7"},
	"GL017": {"CICD-SEC-5"},
	"GL018": {"CICD-SEC-6"},
	"GL019": {"CICD-SEC-1"},
	"GL020": {"CICD-SEC-9"},
	"GL021": {"CICD-SEC-6"},
	"GL022": {"CICD-SEC-3"},
	"GL023": {"CICD-SEC-3"},
	"GL024": {"CICD-SEC-7"},
	"GL025": {"CICD-SEC-9"},
	"GL026": {"CICD-SEC-3"},
	"GL027": {"CICD-SEC-6"},
	"GL028": {"CICD-SEC-7"},
	"GL029": {"CICD-SEC-6"},
	"GL030": {"CICD-SEC-7"},
	"GL031": {"CICD-SEC-7"},
	"GL032": {"CICD-SEC-6"},
	"GL033": {"CICD-SEC-6"},
	"GL034": {"CICD-SEC-1"},
	"GL035": {"CICD-SEC-6"},
	"GL036": {"CICD-SEC-6"},
	"GL037": {"CICD-SEC-6"},
	"GL038": {"CICD-SEC-6"},
	"GL039": {"CICD-SEC-1"},
	"GL040": {"CICD-SEC-6"},
	"GL041": {"CICD-SEC-4", "CICD-SEC-8"},
}

// OWASPCategories returns the OWASP CI/CD security categories for a rule ID.
func OWASPCategories(id string) []string {
	return owaspCategories[id]
}
