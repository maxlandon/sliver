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

	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// HostIOCs - Completes IOCs for hosts, in a separate group for each host
func HostIOCs() (comps []*readline.CompletionGroup) {

	allHosts, err := transport.RPC.Hosts(context.Background(), &commonpb.Empty{})
	if err != nil {
		return
	}

	for _, host := range allHosts.Hosts {
		if len(host.IOCs) == 0 {
			continue
		}

		// Format each Host ID in a group title
		var shortID string
		if len(host.HostUUID) < 8 {
			shortID = host.HostUUID[:len(host.HostUUID)]
		} else {
			shortID = host.HostUUID[:8]
		}
		title := fmt.Sprintf("host %s (%s)", shortID, host.OSVersion)

		// Make group
		comp := &readline.CompletionGroup{
			Name:         title,
			Descriptions: map[string]string{},
			DisplayType:  readline.TabDisplayList,
		}

		// Populate with IOCs
		for _, ioc := range host.IOCs {
			comp.Suggestions = append(comp.Suggestions, ioc.ID)
			desc := fmt.Sprintf("(%s) - %s", ioc.FileHash, ioc.Path)
			comp.Descriptions[shortID] = readline.DIM + desc + readline.RESET
		}

		// Add to comp groups list
		comps = append(comps, comp)
	}

	return comps
}
