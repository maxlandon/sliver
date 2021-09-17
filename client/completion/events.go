package completion

/*
	Sliver Implant Framework
	Copyright (C) 2019  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"github.com/maxlandon/readline"

	"github.com/bishopfox/sliver/client/core"
)

// ReactableEventTypes - Complete reactable events by types
func ReactableEventTypes() (comps []*readline.CompletionGroup) {

	grp := &readline.CompletionGroup{
		Name:        "reactable event types",
		MaxLength:   5,
		DisplayType: readline.TabDisplayGrid,
	}

	for _, eventType := range core.ReactableEvents {
		grp.Suggestions = append(grp.Suggestions, eventType)
	}

	return []*readline.CompletionGroup{grp}
}
