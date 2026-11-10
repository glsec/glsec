// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"fmt"
	"strings"
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
		// A version or help flag alone installs nothing (#1275).
		{"yarn --version + npm publish", `
publish:
  script:
    - yarn --version
    - yarn -v
    - npm publish
`, 0},
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

func TestGL090_SudoCombinedOptions(t *testing.T) {
	f := findings090(t, "publish:\n  script:\n    - sudo -Hu node npm ci\n    - npm publish\n")
	if len(f) != 1 {
		t.Fatalf("expected one finding, got %v", f)
	}
}

func TestGL090_Python(t *testing.T) {
	for _, tc := range []struct {
		name, yaml string
		want       int
	}{
		{"pip install -r + twine upload", `
publish:
  script:
    - pip install -r requirements.txt
    - python -m build
    - twine upload dist/*
`, 1},
		{"poetry install + poetry publish", `
publish:
  script:
    - poetry install
    - poetry publish --build
`, 1},
		{"uv sync + uv publish", `
publish:
  script:
    - uv sync --frozen
    - uv publish
`, 1},
		{"pip install . + python -m twine upload", `
publish:
  script:
    - python3 -m pip install .[dev]
    - python3 -m twine upload dist/*
`, 1},
		{"pip install -e . + flit publish", `
publish:
  script:
    - pip install -e .
    - flit publish
`, 1},
		{"pip install -qr + hatch publish", `
publish:
  script:
    - pip install -qr requirements.txt
    - hatch publish
`, 1},
		{"uv pip install -r + uvx twine upload", `
publish:
  script:
    - uv pip install --system -r requirements.txt
    - uvx twine upload dist/*
`, 1},
		{"pipenv install + poetry run twine upload", `
publish:
  script:
    - pipenv install --deploy
    - poetry run twine upload dist/*
`, 1},
		{"pdm install + pdm publish", `
publish:
  script:
    - pdm install
    - pdm publish
`, 1},
		{"inline PIP_ONLY_BINARY applies to that install only", `
publish:
  script:
    - 'PIP_ONLY_BINARY=:all: pip install -r requirements.txt'
    - pip install .
    - twine upload dist/*
`, 1},
		{"named tool installs", `
publish:
  script:
    - pip install --upgrade pip
    - pip install build twine
    - python -m build
    - twine upload dist/*
`, 0},
		{"own project without dependencies", `
publish:
  script:
    - pip install --no-deps .
    - twine upload dist/*
`, 0},
		{"wheel from dist", `
publish:
  script:
    - pip install ./dist/pkg-1.0-py3-none-any.whl
    - twine upload dist/*
`, 0},
		{"target dir is not a local project", `
publish:
  script:
    - pip install -t ./lib twine
    - twine upload dist/*
`, 0},
		{"--only-binary :all:", `
publish:
  script:
    - 'pip install --only-binary :all: -r requirements.txt'
    - twine upload dist/*
`, 0},
		{"--only-binary=:all:", `
publish:
  script:
    - 'pip install --only-binary=:all: -r requirements.txt'
    - twine upload dist/*
`, 0},
		{"uv sync --no-build", `
publish:
  script:
    - uv sync --no-build
    - uv publish
`, 0},
		{"PIP_ONLY_BINARY variable", `
variables:
  PIP_ONLY_BINARY: ":all:"
publish:
  script:
    - pip install -r requirements.txt
    - twine upload dist/*
`, 0},
		{"UV_NO_BUILD variable", `
publish:
  variables:
    UV_NO_BUILD: "1"
  script:
    - uv sync
    - uv publish
`, 0},
		{"export PIP_ONLY_BINARY", `
publish:
  script:
    - export PIP_ONLY_BINARY=":all:"
    - pip install -r requirements.txt
    - twine upload dist/*
`, 0},
		{"poetry config installer.only-binary", `
publish:
  script:
    - poetry config installer.only-binary ":all:"
    - poetry install
    - poetry publish
`, 0},
		{"build and upload split", `
build:
  script:
    - pip install -r requirements.txt
    - python -m build
  artifacts:
    paths: [dist/]
publish:
  needs: [build]
  script:
    - pip install twine
    - twine upload dist/*
`, 0},
		{"install without publish", `
test:
  script:
    - poetry install
    - poetry run pytest
`, 0},
		{"inline PIP_ONLY_BINARY", `
publish:
  script:
    - 'PIP_ONLY_BINARY=:all: pip install -r requirements.txt'
    - twine upload dist/*
`, 0},
		{"uv pip sync + uv publish", `
publish:
  script:
    - uv pip sync requirements.txt
    - uv publish
`, 1},
		{"--only-binary for one package only", `
publish:
  script:
    - pip install --only-binary numpy -r requirements.txt
    - twine upload dist/*
`, 1},
		{"pip download installs nothing", `
publish:
  script:
    - pip download -r requirements.txt -d wheels
    - twine upload dist/*
`, 0},
		{"POETRY_INSTALLER_ONLY_BINARY variable", `
publish:
  variables:
    POETRY_INSTALLER_ONLY_BINARY: "true"
  script:
    - poetry install
    - poetry publish
`, 0},
		{"uv publish --dry-run", `
package:
  script:
    - uv sync
    - uv publish --dry-run
`, 0},
		{"twine check is no upload", `
check:
  script:
    - pip install -r requirements.txt
    - twine check dist/*
`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := findings090(t, tc.yaml)
			if len(f) != tc.want {
				t.Fatalf("got %d findings, want %d: %+v", len(f), tc.want, f)
			}
			if tc.want == 1 && !strings.Contains(f[0].Message, "--only-binary :all:") {
				t.Errorf("message lacks the Python fix: %s", f[0].Message)
			}
		})
	}
}

func TestGL090_RubyGems(t *testing.T) {
	for _, tc := range []struct {
		name, yaml string
		want       int
	}{
		{"bundle install + gem push", `
release:
  script:
    - bundle install
    - gem build mygem.gemspec
    - gem push mygem-*.gem
`, 1},
		{"bundle --version + gem push", `
release:
  script:
    - bundle --version
    - bundle -h
    - gem push mygem-*.gem
`, 0},
		{"bare bundle + bundle exec rake release", `
release:
  script:
    - bundle
    - bundle exec rake release
`, 1},
		{"named gem install is not the bundle", `
release:
  script:
    - gem install bundler
    - gem build mygem.gemspec
    - gem push mygem-*.gem
`, 0},
		{"bundle exec rake test", `
test:
  script:
    - bundle install
    - bundle exec rake test
`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if f := findings090(t, tc.yaml); len(f) != tc.want {
				t.Fatalf("got %d findings, want %d: %+v", len(f), tc.want, f)
			}
		})
	}
}

func TestGL090_OneFindingPerEcosystem(t *testing.T) {
	f := findings090(t, "publish:\n  script:\n    - npm ci\n    - pip install -r requirements.txt\n    - npm publish\n    - twine upload dist/*\n")
	if len(f) != 2 || f[0].Line != 3 || f[1].Line != 4 {
		t.Fatalf("got %+v, want findings on lines 3 and 4", f)
	}
}

func TestGL090_InheritVariablesList(t *testing.T) {
	src := `
variables:
  NPM_CONFIG_IGNORE_SCRIPTS: "true"
  FOO: bar
publish:
  inherit:
    variables: %s
  script:
    - npm ci
    - npm publish
`
	for _, tc := range []struct {
		inherit string
		want    int
	}{
		{"[FOO]", 1},
		{"false", 1},
		{"true", 0},
		{"[FOO, NPM_CONFIG_IGNORE_SCRIPTS]", 0},
	} {
		if got := checkRule(t, GL090, fmt.Sprintf(src, tc.inherit)); len(got) != tc.want {
			t.Errorf("inherit %s: got %d findings, want %d: %v", tc.inherit, len(got), tc.want, got)
		}
	}
}

func TestGL090_InheritDefaultFromTemplate(t *testing.T) {
	src := `
default:
  before_script:
    - npm ci
.no-defaults:
  inherit:
    default: false
publish:
  extends: .no-defaults
  script:
    - npm publish
`
	if got := checkRule(t, GL090, src); len(got) != 0 {
		t.Errorf("job doesn't run default:before_script, got %v", got)
	}
}

// A protective setting counts only when it takes effect for the install:
// printed text is not a setting, an assignment in front of another command
// applies to that command only, a reset undoes it, and a child shell's
// setting ends with the child (#1301, #1325).
func TestGL090_EffectiveSetting(t *testing.T) {
	job := func(lines ...string) string {
		var b strings.Builder
		b.WriteString("publish:\n  script:\n")
		for _, l := range lines {
			fmt.Fprintf(&b, "    - %q\n", l)
		}
		return b.String()
	}
	for name, tc := range map[string]struct {
		lines []string
		want  int
	}{
		// #1301 reproductions.
		"printed config text":       {[]string{`echo "npm config set ignore-scripts true"`, "npm ci", "npm publish"}, 1},
		"local to another command":  {[]string{"NPM_CONFIG_IGNORE_SCRIPTS=true npm --version", "npm ci", "npm publish"}, 1},
		"set then reset":            {[]string{"npm config set ignore-scripts true", "npm config set ignore-scripts false", "npm ci", "npm publish"}, 1},
		"exported then unset":       {[]string{"export NPM_CONFIG_IGNORE_SCRIPTS=true", "unset NPM_CONFIG_IGNORE_SCRIPTS", "npm ci", "npm publish"}, 1},
		"local reset on install":    {[]string{"export NPM_CONFIG_IGNORE_SCRIPTS=true", "NPM_CONFIG_IGNORE_SCRIPTS=false npm ci", "npm publish"}, 1},
		"printf to stdout":          {[]string{"printf 'ignore-scripts=true\\n' > /dev/null", "npm ci", "npm publish"}, 1},
		"python printed setting":    {[]string{`echo "PIP_ONLY_BINARY=:all:"`, "pip install -r requirements.txt", "twine upload dist/*"}, 1},
		"python local to --version": {[]string{"PIP_ONLY_BINARY=:all: pip --version", "pip install -r requirements.txt", "twine upload dist/*"}, 1},
		"child shell export ends":   {[]string{`bash -c "export NPM_CONFIG_IGNORE_SCRIPTS=true"`, "npm ci", "npm publish"}, 1},
		// Settings that do take effect stay silent.
		"install argument":       {[]string{"npm ci --ignore-scripts", "npm publish"}, 0},
		"assignment on install":  {[]string{"NPM_CONFIG_IGNORE_SCRIPTS=true npm ci", "npm publish"}, 0},
		"env on install":         {[]string{"env NPM_CONFIG_IGNORE_SCRIPTS=true npm ci", "npm publish"}, 0},
		"exported":               {[]string{"export NPM_CONFIG_IGNORE_SCRIPTS=true", "npm ci", "npm publish"}, 0},
		"bare assignment":        {[]string{"NPM_CONFIG_IGNORE_SCRIPTS=true", "npm ci", "npm publish"}, 0},
		"npm config set":         {[]string{"npm config set ignore-scripts true", "npm ci", "npm publish"}, 0},
		"echo into .npmrc":       {[]string{`echo "ignore-scripts=true" >> .npmrc`, "npm ci", "npm publish"}, 0},
		"yarn config":            {[]string{"yarn config set enableScripts false", "yarn install", "npm publish"}, 0},
		"python exported":        {[]string{"export PIP_ONLY_BINARY=:all:", "pip install -r requirements.txt", "twine upload dist/*"}, 0},
		"pip config":             {[]string{"pip config set global.only-binary :all:", "pip install -r requirements.txt", "twine upload dist/*"}, 0},
		"child shell same scope": {[]string{`bash -c "export NPM_CONFIG_IGNORE_SCRIPTS=true; npm ci"`, "npm publish"}, 0},
	} {
		t.Run(name, func(t *testing.T) {
			if f := findings090(t, job(tc.lines...)); len(f) != tc.want {
				t.Errorf("got %d findings %v, want %d", len(f), f, tc.want)
			}
		})
	}
}

// A setting in one job doesn't reach another.
func TestGL090_SettingStaysInItsJob(t *testing.T) {
	f := findings090(t, `protected:
  script:
    - export NPM_CONFIG_IGNORE_SCRIPTS=true
    - npm ci
    - npm publish
open:
  script:
    - npm ci
    - npm publish
`)
	if len(f) != 1 || f[0].Job != "open" {
		t.Fatalf("got %v, want one finding in job open", f)
	}
}
