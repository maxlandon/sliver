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

	"github.com/maxlandon/readline"

	"github.com/bishopfox/sliver/client/command/c2"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// BeaconIDs - Completes beacon IDs along with a description.
func BeaconIDs() (comps []*readline.CompletionGroup) {

	comp := &readline.CompletionGroup{
		Name:         "beacons",
		Descriptions: map[string]string{},
		DisplayType:  readline.TabDisplayList,
	}

	beacons, err := transport.RPC.GetBeacons(context.Background(), &commonpb.Empty{})
	if err != nil {
		return
	}
	for _, b := range beacons.Beacons {
		comp.Suggestions = append(comp.Suggestions, c2.GetShortID(b.ID))
		desc := fmt.Sprintf("[%s] - %s@%s - %s", b.Name, b.Username, b.Hostname, b.RemoteAddress)
		comp.Descriptions[c2.GetShortID(b.ID)] = readline.DIM + desc + readline.RESET
	}

	return []*readline.CompletionGroup{comp}
}
