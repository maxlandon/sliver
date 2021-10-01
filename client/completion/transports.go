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
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/maxlandon/readline"

	c2cmds "github.com/bishopfox/sliver/client/command/c2"
	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// TransportsIDs - Returns the IDs of the transports for a given session
func TransportsIDs() (comps []*readline.CompletionGroup) {

	transports, err := transport.RPC.GetTransports(context.Background(), &clientpb.GetTransportsReq{
		Request: core.ActiveTarget.Request(),
	})
	if err != nil {
		return
	}

	// Completions
	completion := &readline.CompletionGroup{
		Name:         "session transports",
		MaxLength:    10, // The grid system is not yet able to roll on comps if > MaxLength
		DisplayType:  readline.TabDisplayList,
		Descriptions: map[string]string{},
		TrimSlash:    true,
	}

	// Sort the transports by priority
	var keys []int
	for _, t := range transports.Transports {
		keys = append(keys, int(t.Order))
	}
	sort.Ints(keys)

	// Add each transport to the completions
	for _, v := range keys {
		for _, t := range transports.Transports {
			if int(t.Order) != v {
				continue
			}
			c2 := t.Profile

			// Left hand side
			direction := ""
			if c2.Direction == sliverpb.C2Direction_Bind {
				direction = "-->  "
			} else {
				direction = "<--  "
			}
			protocolDirPath := fmt.Sprintf("%-9s %s ", c2.C2, direction) + c2cmds.FullTargetPath(c2)

			// Right hand side
			var name, connSettings, sessionInfo, maxErrors string
			if c2.Type == sliverpb.C2Type_Session {
				name = fmt.Sprintf("%15s", "["+c2.Name+"] ")
				connSettings = fmt.Sprintf("%-8s / %5s", time.Duration(c2.Interval), time.Duration(c2.PollTimeout))
				sessionInfo = fmt.Sprintf("(S) %8s", connSettings)
				maxErrors = fmt.Sprintf("  MaxErr: %-5d", c2.MaxConnectionErrors)
			}

			if c2.Type == sliverpb.C2Type_Beacon {
				name = fmt.Sprintf("%15s", "["+c2.Name+"] ")
				connSettings = fmt.Sprintf("%-8s / %5s", time.Duration(c2.Interval), time.Duration(c2.Jitter))
				sessionInfo = fmt.Sprintf("(B) %8s", connSettings)
				maxErrors = fmt.Sprintf("  MaxErr: %-5d", c2.MaxConnectionErrors)
			}

			// Assemble the complete string
			rightHand := name + sessionInfo + maxErrors
			sWidth := readline.GetTermWidth()
			pad := getPromptPad(sWidth-20, len(protocolDirPath), len(rightHand))
			description := readline.DIM + protocolDirPath + pad + rightHand + readline.RESET

			completion.Suggestions = append(completion.Suggestions, c2cmds.GetShortID(c2.ID))
			completion.Descriptions[c2cmds.GetShortID(c2.ID)] = description
		}
	}

	comps = append(comps, completion)
	return
}
