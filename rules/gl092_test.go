// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings092(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL092.Check(doc.Root, "test.yml")
}

func TestGL092(t *testing.T) {
	for name, tc := range map[string]struct {
		yaml string
		want int
	}{
		"pypi": {`publish:
  id_tokens:
    PYPI_ID_TOKEN:
      aud: pypi
  script:
    - twine upload dist/*
`, 1},
		"testpypi via python -m": {`publish:
  id_tokens:
    PYPI_ID_TOKEN:
      aud: testpypi
  script:
    - python -m twine upload --repository testpypi dist/*
`, 1},
		"uv publish, aud list": {`publish:
  id_tokens:
    PYPI_ID_TOKEN:
      aud: [pypi, sigstore]
  script:
    - uv publish
`, 1},
		"npm": {`publish:
  id_tokens:
    NPM_ID_TOKEN:
      aud: "npm:registry.npmjs.org"
  script:
    - npm ci --ignore-scripts
    - npm publish
`, 1},
		"token from default": {`default:
  id_tokens:
    PYPI_ID_TOKEN:
      aud: pypi
publish:
  script:
    - twine upload dist/*
`, 1},
		"empty environment name": {`publish:
  environment:
    url: https://pypi.org/p/demo
  id_tokens:
    PYPI_ID_TOKEN:
      aud: pypi
  script:
    - twine upload dist/*
`, 1},
		// Not reported.
		"environment string": {`publish:
  environment: release
  id_tokens:
    PYPI_ID_TOKEN:
      aud: pypi
  script:
    - twine upload dist/*
`, 0},
		"environment mapping": {`publish:
  environment:
    name: release
    deployment_tier: production
  id_tokens:
    NPM_ID_TOKEN:
      aud: npm:registry.npmjs.org
  script:
    - npm publish
`, 0},
		"environment from template": {`.release:
  environment: release
publish:
  extends: .release
  id_tokens:
    PYPI_ID_TOKEN:
      aud: pypi
  script:
    - twine upload dist/*
`, 0},
		"environment from default": {`default:
  environment: release
publish:
  id_tokens:
    PYPI_ID_TOKEN:
      aud: pypi
  script:
    - twine upload dist/*
`, 0},
		"no publish command": {`check:
  id_tokens:
    PYPI_ID_TOKEN:
      aud: pypi
  script:
    - twine check dist/*
`, 0},
		"dry run": {`publish:
  id_tokens:
    PYPI_ID_TOKEN:
      aud: pypi
  script:
    - uv publish --dry-run
`, 0},
		"cloud audience": {`deploy:
  id_tokens:
    AWS_ID_TOKEN:
      aud: https://sts.amazonaws.com
  script:
    - twine upload dist/*
`, 0},
		"audience of another registry": {`publish:
  id_tokens:
    PYPI_ID_TOKEN:
      aud: pypi
  script:
    - npm publish
`, 0},
		"publish only printed": {`publish:
  id_tokens:
    PYPI_ID_TOKEN:
      aud: pypi
  script:
    - echo "twine upload dist/*"
`, 0},
		"hidden template": {`.publish:
  id_tokens:
    PYPI_ID_TOKEN:
      aud: pypi
  script:
    - twine upload dist/*
`, 0},
		"template from another file": {`include:
  - local: templates.yml
publish:
  extends: .from-include
  id_tokens:
    PYPI_ID_TOKEN:
      aud: pypi
  script:
    - twine upload dist/*
`, 0},
	} {
		t.Run(name, func(t *testing.T) {
			f := findings092(t, tc.yaml)
			if len(f) != tc.want {
				t.Fatalf("got %d findings %v, want %d", len(f), f, tc.want)
			}
		})
	}
}

// The finding is info, on the token's name, and names the registry and token.
func TestGL092_Finding(t *testing.T) {
	f := findings092(t, `publish:
  id_tokens:
    NPM_ID_TOKEN:
      aud: npm:registry.npmjs.org
    PYPI_ID_TOKEN:
      aud: pypi
  script:
    - npm publish
    - twine upload dist/*
`)
	if len(f) != 2 {
		t.Fatalf("got %v, want one finding per token", f)
	}
	for i, want := range []struct {
		line          int
		registry, tok string
	}{{3, "npm", "NPM_ID_TOKEN"}, {5, "PyPI", "PYPI_ID_TOKEN"}} {
		if f[i].Severity != finding.Info || f[i].Line != want.line ||
			!strings.Contains(f[i].Message, "publishes to "+want.registry) || !strings.Contains(f[i].Message, want.tok) {
			t.Errorf("finding %d: %+v, want info on line %d naming %s and %s", i, f[i], want.line, want.registry, want.tok)
		}
	}
}
