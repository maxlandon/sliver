package reaction

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

	"github.com/maxlandon/readline"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
)

// Unset - Unset a reaction to an event
type Unset struct {
	Positional struct {
		ReactionID []int `description:"ID of reaction(s) to unset" required:"1"`
	} `positional-args:"yes" required:"yes"`
}

// Execute - Unset a reaction to an event
func (r *Unset) Execute(args []string) (err error) {

	for _, reac := range core.Reactions.All() {
		for _, id := range r.Positional.ReactionID {
			if id == reac.ID {
				success := core.Reactions.Remove(id)
				if !success {
					err := log.Errorf("Did not found reaction %s%s%s",
						readline.RED, reac.ID, readline.RESET)
					fmt.Printf(err.Error())
					continue
				}
				log.Infof("Removed reaction %s%s%s [%s] - (%d commands)",
					readline.BLUE, reac.ID, readline.RESET, EventTypeToTitle(reac.EventType), len(reac.Commands))
			}
		}
	}

	return
}
