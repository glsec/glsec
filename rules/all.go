package rules

import "github.com/glsec/glsec/internal/rule"

func All() []rule.Rule {
	return []rule.Rule{
		GL001,
		GL002,
		GL003,
		GL004,
		GL005,
		GL006,
		GL007,
	}
}
