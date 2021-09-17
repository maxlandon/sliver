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
	"strconv"

	"github.com/maxlandon/readline"

	consts "github.com/bishopfox/sliver/client/constants"
	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
)

// Reaction - Event reaction management
type Reaction struct {
	Options struct {
		Types []string `long:"types" short:"t" description:"Comma-separated list of event types to limit display to"`
	} `group:"loot fetch options"`
}

// Execute - Event reaction management. Displays all reactions by default
func (r *Reaction) Execute(args []string) (err error) {
	totalReactions := 0
	for _, eventType := range core.ReactableEvents {

		// First determine if we have filters and if we pass the test for this event type.
		var display = true // by default
		if len(r.Options.Types) > 0 {
			display = false
			for _, filter := range r.Options.Types {
				if filter == eventType {
					display = true
				}
			}
		}
		if !display {
			continue
		}
		reactions := core.Reactions.On(eventType)
		if len(reactions) == 0 {
			continue
		}

		// Then print
		fmt.Printf("%s %s %s\n", readline.YELLOW, EventTypeToTitle(eventType), readline.RESET)

		for i, react := range reactions {
			for j, cmd := range react.Commands {

				// Make a special prompt for first command of the reaction, and print anyway
				var prompt string
				if j == 0 {
					prompt = readline.DIM + strconv.Itoa(j) + fmt.Sprintf("reac%d > ", i) + readline.RESET
				} else {
					prompt = readline.DIM + strconv.Itoa(j) + "       > " + readline.RESET
				}
				fmt.Printf(prompt + cmd + "\n")
			}
		}
		totalReactions += len(reactions)
	}
	if totalReactions == 0 {
		log.Infof("No reactions set")
		return
	}
	return
}

// EventTypeToTitle - Convert an eventType to a more human friendly string
func EventTypeToTitle(eventType string) string {
	switch eventType {

	case consts.SessionOpenedEvent:
		return "Session Opened"
	case consts.SessionClosedEvent:
		return "Session Closed"
	case consts.SessionUpdateEvent:
		return "Session Updated"

	case consts.CanaryEvent:
		return "Canary Trigger"

	case consts.WatchtowerEvent:
		return "Watchtower Trigger"

	default:
		return eventType
	}
}
