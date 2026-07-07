// Teleport
// Copyright (C) 2026 Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"slices"
	"testing"

	"golang.org/x/tools/go/analysis"
)

// messages extracts the Message field from each Finding, so tests can
// compare on message content without asserting on Pos.
func messages(findings []Finding) []string {
	msgs := make([]string, len(findings))
	for i, f := range findings {
		msgs[i] = f.Message
	}
	return msgs
}

func TestCheckTargets(t *testing.T) {
	tests := []struct {
		name    string
		pkgPath string
		src     string
		targets []Target
		want    []Finding
	}{
		// TODO: add cases for:
		// - BadParameter call with a docs URL via a named constant (no findings; needs either
		//   real type-checking in the test harness, or a same-file AST scan for const decls)
		// - docs URL split across a string concatenation (`"a" + "b" + url`), e.g. mirroring
		//   tsh.go's mlockFailureMessage constant; stringLiteralValue only handles a single
		//   *ast.BasicLit today, not a *ast.BinaryExpr chain, so this would need its own
		//   resolution logic even after named-constant resolution is added
		// - message containing a non-Teleport URL, e.g. https://git-scm.com/... (should still
		//   report; regression guard for the false positive we hit scanning tool/tsh manually)
		// - two BadParameter calls without docs URLs in the same target function (expect two
		//   findings, not one)
		// - empty/nil targets against a source with a real violation (expect no findings)
		{
			name:    "bad parameter without docs url",
			pkgPath: "p",
			src: `package p

import "github.com/gravitational/trace"

func onExample() error {
	return trace.BadParameter("something went wrong")
}
`,
			targets: []Target{
				{Package: "p", Function: "onExample"},
			},
			want: []Finding{
				{Message: "trace.BadParameter call does not link to Teleport documentation"},
			},
		},
		{
			name:    "bad parameter with docs url",
			pkgPath: "p",
			src: `package p

import "github.com/gravitational/trace"

func onExample() error {
	return trace.BadParameter("something went wrong, see https://goteleport.com/docs/reference/example/ for details")
}
`,
			targets: []Target{
				{Package: "p", Function: "onExample"},
			},
			want: nil,
		},
		{
			name:    "violation outside target function",
			pkgPath: "p",
			src: `package p

import "github.com/gravitational/trace"

func onExample() error {
	return nil
}

func notATarget() error {
	return trace.BadParameter("something went wrong")
}
`,
			targets: []Target{
				{Package: "p", Function: "onExample"},
			},
			want: nil,
		},
		{
			// Mirrors a real collision found in tool/tsh, tool/tctl, and tool/tbot: each has
			// its own top-level Run function, and tool/tsh/common and tool/tctl/common even
			// share the identical bare package name "common". A target for one package's Run
			// must not pick up a same-named Run in a different package.
			name:    "different package, same function name",
			pkgPath: "github.com/gravitational/teleport/tool/tsh/common",
			src: `package common

import "github.com/gravitational/trace"

func Run() error {
	return trace.BadParameter("something went wrong")
}
`,
			targets: []Target{
				{Package: "github.com/gravitational/teleport/tool/tctl/common", Function: "Run"},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "test.go", tt.src, 0)
			if err != nil {
				t.Fatalf("parsing source: %v", err)
			}

			pass := &analysis.Pass{
				Fset:  fset,
				Files: []*ast.File{f},
				Pkg:   types.NewPackage(tt.pkgPath, f.Name.Name),
			}

			got := checkTargets(pass, tt.targets)

			if !slices.Equal(messages(got), messages(tt.want)) {
				t.Errorf("checkTargets() = %v, want %v", messages(got), messages(tt.want))
			}
		})
	}
}
