// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings090(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL090.Check(doc.Root, "test.yml")
}

func TestGL090(t *testing.T) {
	for _, tc := range []struct {
		name, yaml string
		want       int
	}{
		{"npm ci + npm publish", `
publish:
  variables:
    NPM_TOKEN: $NPM_PUBLISH_TOKEN
  script:
    - npm ci
    - npm publish
`, 1},
		{"npm install + npm publish", `
publish:
  script:
    - npm install
    - npm run build
    - npm publish --access public
`, 1},
		{"yarn install + yarn npm publish", `
publish:
  script:
    - yarn install --immutable
    - yarn npm publish
`, 1},
		{"bare yarn + yarn publish", `
publish:
  script:
    - yarn
    - yarn publish --non-interactive
`, 1},
		{"install in before_script, publish in script", `
publish:
  before_script:
    - npm ci
  script:
    - npm publish
`, 1},
		{"install from default before_script", `
default:
  before_script:
    - npm ci
publish:
  script:
    - npm publish
`, 1},
		{"install inherited via extends", `
.node:
  before_script:
    - npm ci
publish:
  extends: .node
  script:
    - npm publish
`, 1},
		{"npm ci + pnpm publish", `
publish:
  script:
    - npm ci && pnpm -r publish --no-git-checks
`, 1},
		{"sudo npm ci + publish", `
publish:
  script:
    - sudo npm ci
    - npm publish
`, 1},
		{"global tool install is not the dependency tree", `
publish:
  script:
    - npm install -g npm@11.6.2
    - yarn global add semver
    - npm publish --provenance
`, 0},
		{"global tool, then npm ci", `
publish:
  script:
    - npm install --global npm@11.6.2
    - npm ci
    - npm publish
`, 1},
		{"inline assignment applies to that install only", `
publish:
  script:
    - NPM_CONFIG_IGNORE_SCRIPTS=true npm ci
    - npm install extra-tool
    - npm publish
`, 1},
		{"--ignore-scripts", `
publish:
  script:
    - npm ci --ignore-scripts
    - npm publish
`, 0},
		{"NPM_CONFIG_IGNORE_SCRIPTS job variable", `
publish:
  variables:
    NPM_CONFIG_IGNORE_SCRIPTS: "true"
  script:
    - npm ci
    - npm publish
`, 0},
		{"npm_config_ignore_scripts global variable", `
variables:
  npm_config_ignore_scripts: "true"
publish:
  script:
    - npm ci
    - npm publish
`, 0},
		{"inline NPM_CONFIG_IGNORE_SCRIPTS", `
publish:
  script:
    - NPM_CONFIG_IGNORE_SCRIPTS=true npm ci
    - npm publish
`, 0},
		{"npm config set ignore-scripts before install", `
publish:
  script:
    - npm config set ignore-scripts true
    - npm ci
    - npm publish
`, 0},
		{".npmrc line before install", `
publish:
  script:
    - echo "ignore-scripts=true" >> .npmrc
    - npm ci
    - npm publish
`, 0},
		{"YARN_ENABLE_SCRIPTS false", `
publish:
  variables:
    YARN_ENABLE_SCRIPTS: "false"
  script:
    - yarn install --immutable
    - yarn npm publish
`, 0},
		{"yarn --mode=skip-build", `
publish:
  script:
    - yarn install --mode=skip-build
    - yarn npm publish
`, 0},
		{"build and publish split", `
build:
  script:
    - npm ci
    - npm run build
  artifacts:
    paths: [dist/]
publish:
  needs: [build]
  script:
    - npm publish
`, 0},
		{"publish only", `
publish:
  script:
    - npm publish
`, 0},
		{"pnpm install is not listed", `
publish:
  script:
    - pnpm install --frozen-lockfile
    - pnpm publish
`, 0},
		{"install without publish", `
test:
  script:
    - npm ci
    - npm test
`, 0},
		{"hidden job", `
.publish:
  script:
    - npm ci
    - npm publish
`, 0},
		{"publish inside echo", `
publish:
  script:
    - npm ci
    - echo "run npm publish manually"
`, 0},
		{"yarn run script named publish", `
publish:
  script:
    - yarn install
    - yarn run publish-docs
`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := findings090(t, tc.yaml)
			if len(f) != tc.want {
				t.Fatalf("got %d findings, want %d: %+v", len(f), tc.want, f)
			}
			if tc.want == 1 && (f[0].Severity != finding.Warn || f[0].Job != "publish") {
				t.Errorf("unexpected finding: %+v", f[0])
			}
		})
	}
}

func TestGL090_ReportsInstallLine(t *testing.T) {
	f := findings090(t, "publish:\n  script:\n    - |\n      echo start\n      npm ci\n    - npm publish\n")
	if len(f) != 1 || f[0].Line != 5 {
		t.Fatalf("got %+v, want one finding on line 5", f)
	}
}
