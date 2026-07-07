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

	consts := packageConstants(pass.Files)

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

				msg, ok := resolveMessage(msgArg, consts)
				if !ok {
					// Neither a plain string literal nor a reference to a
					// resolvable constant (e.g. a local variable, or a
					// concatenated expression); can't verify statically yet.
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

// resolveStringExpr returns the string value of expr, handling either a
// plain string literal or a chain of literals joined by string
// concatenation (e.g. "a" + "b" + "c", as in tsh.go's mlockFailureMessage).
func resolveStringExpr(expr ast.Expr) (string, bool) {
	if v, ok := stringLiteralValue(expr); ok {
		return v, true
	}

	bin, ok := expr.(*ast.BinaryExpr)
	if !ok || bin.Op != token.ADD {
		return "", false
	}

	left, ok := resolveStringExpr(bin.X)
	if !ok {
		return "", false
	}
	right, ok := resolveStringExpr(bin.Y)
	if !ok {
		return "", false
	}
	return left + right, true
}

// packageConstants returns a map from constant name to its declared value
// expression, scanned across every file in files. Constants are commonly
// declared in a separate file (e.g. constants.go) from where they're used,
// so this looks across the whole package rather than just one file.
func packageConstants(files []*ast.File) map[string]ast.Expr {
	consts := make(map[string]ast.Expr)
	for _, file := range files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i < len(vs.Values) {
						consts[name.Name] = vs.Values[i]
					}
				}
			}
		}
	}
	return consts
}

// resolveMessage returns the string value of expr, resolving a reference to
// a package-level constant (via consts) if expr isn't itself a literal.
//
// TODO: resolve call.Fun via pass.TypesInfo.Uses to confirm an identifier
// really refers to a constant in this package, not a shadowing local
// variable with the same name.
func resolveMessage(expr ast.Expr, consts map[string]ast.Expr) (string, bool) {
	if v, ok := resolveStringExpr(expr); ok {
		return v, true
	}

	id, ok := expr.(*ast.Ident)
	if !ok {
		return "", false
	}

	value, ok := consts[id.Name]
	if !ok {
		return "", false
	}

	return resolveStringExpr(value)
}
