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
	"fmt"
	"strconv"
	"strings"

	"github.com/maxlandon/readline"

	"github.com/bishopfox/sliver/client/command/server/reaction"
	"github.com/bishopfox/sliver/client/core"
)

// ReactionIDs - Get all reactions IDs and a description
func ReactionIDs() (comps []*readline.CompletionGroup) {

	// Make group
	comp := &readline.CompletionGroup{
		Name:         "reaction IDs",
		Descriptions: map[string]string{},
		DisplayType:  readline.TabDisplayList,
	}

	for _, reac := range core.Reactions.All() {
		comp.Suggestions = append(comp.Suggestions, strconv.Itoa(reac.ID))
		desc := fmt.Sprintf("(%s) - %s", reaction.EventTypeToTitle(reac.EventType), strings.Join(reac.Commands, ","))
		comp.Descriptions[strconv.Itoa(reac.ID)] = readline.DIM + desc + readline.RESET
	}

	return []*readline.CompletionGroup{comp}
}
