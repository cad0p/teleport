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
	"go/token"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// Finding describes a single trace.BadParameter call, within one of the
// given targets, whose message doesn't reference Teleport documentation.
type Finding struct {
	Pos     token.Pos
	Message string
}

const docsURLSubstring = "goteleport.com/docs"

// checkTargets inspects pass for trace.BadParameter calls within the given
// targets, returning a Finding for each one that doesn't reference Teleport
// documentation.
func checkTargets(pass *analysis.Pass, targets []Target) []Finding {
	relevant := targetFunctions(targets, pass.Pkg.Path())
	if len(relevant) == 0 {
		return nil
	}

	var findings []Finding
	for _, file := range pass.Files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !relevant[fn.Name.Name] {
				continue
			}

			ast.Inspect(fn, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}

				msgArg, ok := badParameterMessageArg(call)
				if !ok {
					return true
				}

				msg, ok := stringLiteralValue(msgArg)
				if !ok {
					// Not a plain string literal (e.g. a variable or a
					// named constant); can't verify statically yet.
					return true
				}

				if !strings.Contains(strings.ToLower(msg), docsURLSubstring) {
					findings = append(findings, Finding{
						Pos:     call.Pos(),
						Message: "trace.BadParameter call does not link to Teleport documentation",
					})
				}

				return true
			})
		}
	}

	return findings
}

// targetFunctions returns the set of function names from targets that apply
// to the package at pkgPath.
func targetFunctions(targets []Target, pkgPath string) map[string]bool {
	fns := make(map[string]bool)
	for _, t := range targets {
		if t.Package == pkgPath {
			fns[t.Function] = true
		}
	}
	return fns
}

// badParameterMessageArg returns the message argument of call, if call is a
// trace.BadParameter call.
//
// TODO: resolve call.Fun via pass.TypesInfo.Uses to confirm this is really
// gravitational/trace.BadParameter, not a same-named local function.
func badParameterMessageArg(call *ast.CallExpr) (ast.Expr, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "BadParameter" || len(call.Args) == 0 {
		return nil, false
	}
	return call.Args[0], true
}

// stringLiteralValue returns the string value of expr, if expr is a string
// literal.
//
// TODO: also resolve references to string constants (e.g. via
// pass.TypesInfo and go/constant, or a same-file AST scan of const decls).
func stringLiteralValue(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return v, true
}
