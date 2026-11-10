// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strconv"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings069(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL069.Check(doc.Root, "test.yml")
}

func TestGL069_Flagged(t *testing.T) {
	flagged := []string{
		"apt-get install -y --allow-unauthenticated somepkg",
		"apt-get -o APT::Get::AllowUnauthenticated=true install -y foo",
		`echo "deb [trusted=yes] http://repo.example/ ./" >> /etc/apt/sources.list`,
		`echo "deb [arch=amd64 trusted=yes] http://repo/ ./" >> sources.list`,
		"apk add --allow-untrusted somepkg",
		"GOSUMDB=off go build ./...",
		`GOSUMDB="off" go mod download`,
		"GONOSUMDB=* go mod download",
		"GOINSECURE=* go test ./...",
	}
	for _, line := range flagged {
		f := findings069(t, "job:\n  script:\n    - '"+escapeSingle(line)+"'\n")
		if len(f) != 1 {
			t.Errorf("expected 1 finding for %q, got %d", line, len(f))
			continue
		}
		if f[0].RuleID != "GL069" || f[0].Severity != finding.Warn {
			t.Errorf("unexpected finding for %q: %+v", line, f[0])
		}
	}
}

func TestGL069_MoreManagers(t *testing.T) {
	for _, tc := range []struct {
		script  string
		flagged bool
	}{
		{"dnf update -y --nogpgcheck", true},
		{"dnf install -y --nogpgcheck $DEPENDENCIES", true},
		{"yum install --nogpgcheck pkg", true},
		{"microdnf install --nogpgcheck pkg", true},
		{"tdnf install --nogpgcheck pkg", true},
		{"dnf5 install --nogpgcheck pkg", true},
		{"sudo dnf -y --nogpgcheck upgrade", true},
		{"dnf builddep -y --nogpgcheck msitools", true},
		{"dnf install -y \\\n  gcc \\\n  --nogpgcheck", true},
		{"dnf install -y --nogpgcheck ./a.rpm gcc", true},
		{"dnf install -y --nogpgcheck https://example.com/x.rpm", true},
		{"dnf install --setopt=gpgcheck=0 pkg", true},
		{"zypper --no-gpg-checks install pkg", true},
		{"echo 'gpgcheck=0' >> /etc/yum.repos.d/x.repo", true},
		{`echo -e "[r]\nbaseurl=$U\ngpgcheck=0" > /etc/yum.repos.d/r.repo`, true},
		{"sed -i 's/gpgcheck=1/gpgcheck = 0/' /etc/yum.repos.d/x.repo", true},
		{"apt-get --allow-insecure-repositories update", true},
		{"apt-get -o Acquire::AllowInsecureRepositories=true update", true},
		{`echo 'Acquire::AllowInsecureRepositories "true";' > /etc/apt/apt.conf.d/99x`, true},
		{"sed -i 's/^SigLevel.*/SigLevel = Never/' /etc/pacman.conf", true},
		{`echo "RemoteFileSigLevel = Never" >> /etc/pacman.conf`, true},

		{"dnf --nogpgcheck localinstall ./build/x.rpm", false},
		{"dnf --nogpgcheck localinstall -y build/RPMS/x86_64/*.rpm", false},
		{"dnf -y --setopt=install_weak_deps=True --nogpgcheck install ./*.rpm", false},
		{"yum install --nogpgcheck build/x.rpm", false},
		{"zypper --no-gpg-checks --no-remote install ./x.rpm", false},
		{"zypper --no-gpg-checks in ./x.rpm", false},
		{"dnf install -y pkg", false},
		{"dnf install -y pkg && other --nogpgcheck", false},
		{"gpgcheck=1", false},
		{"echo 'repo_gpgcheck=0' >> /etc/dnf/dnf.conf", false},
		{"echo 'localpkg_gpgcheck=0' >> /etc/dnf/dnf.conf", false},
		{"sed -i 's/^SigLevel.*/SigLevel = Required DatabaseOptional/' /etc/pacman.conf", false},
		{"echo 'Acquire::AllowInsecureRepositories \"false\";'", false},
		{"make\n# SigLevel = Never\n  # dnf update --nogpgcheck\ntrue", false},
	} {
		t.Run(tc.script, func(t *testing.T) {
			f := findings069(t, "build:\n  script:\n    - "+strconv.Quote(tc.script)+"\n")
			if tc.flagged != (len(f) == 1) {
				t.Fatalf("flagged = %v, got %v", tc.flagged, f)
			}
		})
	}
}

// The finding sits on the command's line in a block.
func TestGL069_LineInABlock(t *testing.T) {
	f := findings069(t, "build:\n  script:\n    - |\n      make\n      dnf install -y --nogpgcheck pkg\n")
	if len(f) != 1 || f[0].Line != 5 {
		t.Fatalf("got %v, want one finding on line 5", f)
	}
}

func TestGL069_FlaggedVariables(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{
			"global GOSUMDB off",
			"variables:\n  GOSUMDB: \"off\"\njob:\n  script:\n    - go mod download\n",
		},
		{
			"job GOSUMDB off",
			"job:\n  variables:\n    GOSUMDB: \"off\"\n  script:\n    - go mod download\n",
		},
		{
			"global GONOSUMDB wildcard",
			"variables:\n  GONOSUMDB: \"*\"\njob:\n  script:\n    - go mod download\n",
		},
		{
			"job GOINSECURE wildcard",
			"job:\n  variables:\n    GOINSECURE: \"*\"\n  script:\n    - go mod download\n",
		},
		{
			"default block GOSUMDB off",
			"default:\n  variables:\n    GOSUMDB: \"off\"\njob:\n  script:\n    - go mod download\n",
		},
		{
			"extended variable form",
			"variables:\n  GOSUMDB:\n    value: \"off\"\n    description: skip checksum db\njob:\n  script:\n    - go mod download\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := findings069(t, tc.yaml)
			if len(f) != 1 {
				t.Fatalf("expected 1 finding, got %d: %+v", len(f), f)
			}
			if f[0].RuleID != "GL069" || f[0].Severity != finding.Warn {
				t.Errorf("unexpected finding: %+v", f[0])
			}
		})
	}
}

func TestGL069_NotFlagged(t *testing.T) {
	clean := []string{
		"apt-get install -y somepkg",                                // normal install
		"apk add somepkg",                                           // normal apk
		`echo "deb [signed-by=/k.gpg] https://r/ ./"`,               // verified source
		"apt-key add key.gpg",                                       // intentionally out of scope
		"add-apt-repository ppa:openmw/openmw",                      // intentionally out of scope
		"# apt-get install --allow-unauthenticated x",               // comment
		"gcloud run deploy svc --allow-unauthenticated --region us", // GCP Cloud Run public access, not apt
		"apk add curl",                                              // normal apk
		"go mod download",                                           // verification left on
		"GOSUMDB=sum.golang.org go build ./...",                     // explicit checksum db
		"GOPRIVATE=gitlab.example.com go mod download",              // private modules, verification kept
	}
	for _, line := range clean {
		if f := findings069(t, "job:\n  script:\n    - '"+escapeSingle(line)+"'\n"); len(f) != 0 {
			t.Errorf("expected no finding for %q, got %d: %+v", line, len(f), f)
		}
	}
}

func TestGL069_NotFlaggedVariables(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{
			"private host is the normal setup",
			"variables:\n  GONOSUMDB: \"gitlab.example.com/*\"\njob:\n  script:\n    - go mod download\n",
		},
		{
			"GOPRIVATE scoped to a host",
			"variables:\n  GOPRIVATE: \"gitlab.example.com\"\njob:\n  script:\n    - go mod download\n",
		},
		{
			"GOSUMDB left at its default",
			"variables:\n  GOSUMDB: \"sum.golang.org\"\njob:\n  script:\n    - go mod download\n",
		},
		{
			"GOINSECURE scoped to a host",
			"variables:\n  GOINSECURE: \"gitlab.example.com\"\njob:\n  script:\n    - go mod download\n",
		},
		{
			"unrelated variable",
			"variables:\n  GOFLAGS: \"-mod=readonly\"\njob:\n  script:\n    - go mod download\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if f := findings069(t, tc.yaml); len(f) != 0 {
				t.Errorf("expected no finding, got %d: %+v", len(f), f)
			}
		})
	}
}

func TestGL069_DockerContentTrust(t *testing.T) {
	for _, tc := range []struct {
		name    string
		yaml    string
		flagged bool
	}{
		{"export in script", "job:\n  script:\n    - export DOCKER_CONTENT_TRUST=0\n", true},
		{"env prefix on pull", "job:\n  script:\n    - DOCKER_CONTENT_TRUST=0 docker pull registry.example.com/app:latest\n", true},
		{"disable-content-trust flag", "job:\n  script:\n    - docker pull --disable-content-trust app:latest\n", true},
		{"disable-content-trust on run", "job:\n  script:\n    - docker run --disable-content-trust app:latest\n", true},
		{"global variable", "variables:\n  DOCKER_CONTENT_TRUST: \"0\"\njob:\n  script:\n    - docker pull app:latest\n", true},
		{"global variable unquoted", "variables:\n  DOCKER_CONTENT_TRUST: 0\njob:\n  script:\n    - docker pull app:latest\n", true},
		{"content trust on", "variables:\n  DOCKER_CONTENT_TRUST: \"1\"\njob:\n  script:\n    - docker pull app@sha256:abc\n", false},
		{"content trust env on", "job:\n  script:\n    - DOCKER_CONTENT_TRUST=1 docker pull app:latest\n", false},
		{"digest pull", "job:\n  script:\n    - docker pull app@sha256:abc\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := findings069(t, tc.yaml)
			if tc.flagged != (len(f) == 1) {
				t.Fatalf("got %d findings, want %v: %+v", len(f), tc.flagged, f)
			}
		})
	}
}

func escapeSingle(s string) string {
	out := ""
	for _, r := range s {
		if r == '\'' {
			out += "''"
			continue
		}
		out += string(r)
	}
	return out
}
