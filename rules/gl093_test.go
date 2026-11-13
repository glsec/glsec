// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"

	"github.com/glsec/glsec/internal/finding"
	"github.com/glsec/glsec/internal/parser"
)

func findings093(t *testing.T, yaml string) []finding.Finding {
	t.Helper()
	doc, err := parser.Parse([]byte(yaml), "test.yml")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return GL093.Check(doc.Root, "test.yml")
}

func TestGL093_DisguisedExec(t *testing.T) {
	for _, line := range []string{
		"node assets/fa-brands-400.ttf",
		"python resources/logo.png",
		"bun ./public/fonts/x.woff2",
		"ruby data/blob.bin",
		"perl /tmp/update.dat",
		"php cache/page.svg",
		"Rscript report.pdf",
		"pwsh logo.ico",
		"deno run --allow-all data/x.bin",
		"bun run payload.ttf",
		"node --experimental-vm-modules fonts/x.woff",
		"node server.js && node payload.ttf", // the second command
		"./node_modules/.bin/node assets/x.eot",
	} {
		t.Run(line, func(t *testing.T) {
			f := findings093(t, "j:\n  script:\n    - "+line+"\n")
			if len(f) == 0 {
				t.Fatalf("expected a GL093 finding for %q", line)
			}
			if f[0].Severity != finding.Error || !strings.Contains(f[0].Message, "non-script file") {
				t.Errorf("unexpected finding %+v", f[0])
			}
		})
	}
}

func TestGL093_NoFinding(t *testing.T) {
	for _, line := range []string{
		"node dist/index.mjs",
		"python main.py",
		"python3 manage.py migrate",
		"ruby app.rb",
		"perl script.pl",
		"node -e \"console.log(1)\"",
		"python -c 'print(1)'",
		"python -m http.server",
		"node",                         // REPL, no file
		"bun x create-vite@latest app", // GL022's area, not a data-ext file
		"deno run server.ts",
		"python run.py",                         // "run" is part of the filename, not the deno/bun subcommand
		"echo \"run node payload.ttf locally\"", // prose, quote-masked
		"# node payload.ttf",                    // comment
		"terraform plan",
	} {
		t.Run(line, func(t *testing.T) {
			f := findings093(t, "j:\n  script:\n    - "+line+"\n")
			if len(f) != 0 {
				t.Fatalf("expected no GL093 finding for %q, got %+v", line, f)
			}
		})
	}
}

func TestGL093_PositionAndJob(t *testing.T) {
	f := findings093(t, "deploy:\n  script:\n    - make build\n    - node fonts/x.ttf\n")
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1", len(f))
	}
	if f[0].Job != "deploy" || f[0].Line != 4 {
		t.Errorf("got job %q line %d, want deploy line 4", f[0].Job, f[0].Line)
	}
}

// block093 wraps a single command in a literal `|` block script item, the form
// the #1413 acceptance cases use: quoting and child shells must be resolved the
// same whether the command is a plain item or a block line.
func block093(t *testing.T, command string) []finding.Finding {
	t.Helper()
	return findings093(t, "j:\n  script:\n    - |\n      "+command+"\n")
}

// TestGL093_CommandPosition covers #1413: a quoted interpreter or operand and a
// child-shell payload must flag, while an interpreter that is only an argument
// to another command (echo) or sits in an inline comment must stay silent.
func TestGL093_CommandPosition(t *testing.T) {
	flagged := []string{
		`node fonts/x.ttf`,           // bare (kept)
		`node "fonts/x.ttf"`,         // quoted operand
		`"node" fonts/x.ttf`,         // quoted command name
		`'node' "fonts/x.ttf"`,       // both quoted
		`bash -c 'node fonts/x.ttf'`, // child-shell payload
		`sh -c "node fonts/x.ttf"`,   // child-shell payload, double-quoted
	}
	for _, c := range flagged {
		t.Run("flag/"+c, func(t *testing.T) {
			f := block093(t, c)
			if len(f) == 0 {
				t.Fatalf("expected a GL093 finding for %q", c)
			}
			if f[0].Severity != finding.Error || !strings.Contains(f[0].Message, "non-script file") {
				t.Errorf("unexpected finding %+v", f[0])
			}
		})
	}

	silent := []string{
		`echo node fonts/x.ttf`,          // interpreter is echo's argument (data)
		`echo ok # node fonts/x.ttf`,     // interpreter in an inline comment
		`echo "node payload.ttf"`,        // interpreter inside a quoted argument
		`printf 'node payload.ttf\n'`,    // same, printf
		`node -e 'require("./x.ttf")'`,   // inline code, not a file operand
		`python -c 'open("x.ttf")'`,      // inline code
		`python -m http.server`,          // module invocation
		`node --experimental-vm-modules`, // flag only, no file
		`node app.js`,                    // real script file
		`python run.py`,                  // real script file
		`bash deploy.sh`,                 // bash is not an interpreter here
		`deno run server.ts`,             // real .ts via run subcommand
	}
	for _, c := range silent {
		t.Run("silent/"+c, func(t *testing.T) {
			f := block093(t, c)
			if len(f) != 0 {
				t.Fatalf("expected no GL093 finding for %q, got %+v", c, f)
			}
		})
	}
}
