// Copyright The glsec Authors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// Package-level expressions in the rules use mustCompilePrefiltered, so they
// compile on first use and get the literal prefilter (#1334). A plain
// regexp.MustCompile there is compiled at every start of glsec.
func TestNoPackageLevelMustCompile(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			ast.Inspect(gd, func(n ast.Node) bool {
				if _, ok := n.(*ast.FuncLit); ok {
					return false
				}
				if s, ok := n.(*ast.SelectorExpr); ok && s.Sel.Name == "MustCompile" {
					if id, ok := s.X.(*ast.Ident); ok && id.Name == "regexp" {
						t.Errorf("%s: package-level regexp.MustCompile; use mustCompilePrefiltered", fset.Position(s.Pos()))
					}
				}
				return true
			})
		}
	}
}
