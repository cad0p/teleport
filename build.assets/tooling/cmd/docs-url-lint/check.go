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
	"go/token"

	"golang.org/x/tools/go/analysis"
)

// Finding describes a single trace.BadParameter call, within one of the
// given targets, whose message doesn't reference Teleport documentation.
type Finding struct {
	Pos     token.Pos
	Message string
}

// checkTargets inspects pass for trace.BadParameter calls within the given
// targets, returning a Finding for each one that doesn't reference Teleport
// documentation.
func checkTargets(pass *analysis.Pass, targets []Target) []Finding {
	return nil
}
