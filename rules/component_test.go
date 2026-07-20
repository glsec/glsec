package rules

import "testing"

func TestAppliesToComponentTemplate(t *testing.T) {
	if AppliesToComponentTemplate("GL053") {
		t.Error("GL053 checks for an absent top-level workflow: block, so it cannot apply to a fragment")
	}
	for _, id := range []string{"GL001", "GL002", "GL043", "GL074", "GL080"} {
		if !AppliesToComponentTemplate(id) {
			t.Errorf("%s should still apply to component templates", id)
		}
	}
}
