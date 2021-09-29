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

import "github.com/maxlandon/readline"

// TransportsIDs - Returns the IDs of the transports for a given session
func TransportsIDs() (comps []*readline.CompletionGroup) {

	// Completions
	completion := &readline.CompletionGroup{
		Name:        "session transports",
		MaxLength:   10, // The grid system is not yet able to roll on comps if > MaxLength
		DisplayType: readline.TabDisplayList,
		TrimSlash:   true,
	}

	comps = append(comps, completion)
	return
}
