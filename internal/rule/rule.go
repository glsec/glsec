package rule

import (
	"github.com/glsec/glsec/internal/finding"
	"gopkg.in/yaml.v3"
)

type Rule interface {
	ID() string
	Check(doc *yaml.Node, file string) []finding.Finding
}
