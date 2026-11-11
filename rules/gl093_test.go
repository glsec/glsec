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
