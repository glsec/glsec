package rules

import "github.com/glsec/glsec/internal/rule"

func All() []rule.Rule {
	return []rule.Rule{
		GL001,
	}
}
