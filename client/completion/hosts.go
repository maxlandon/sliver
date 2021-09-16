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
	"strconv"

	"github.com/maxlandon/readline"

	"github.com/bishopfox/sliver/client/command/server/hosts"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// HostUUIDs - Completes hosts UUIDs along with a description.
func HostUUIDs() (comps []*readline.CompletionGroup) {

	comp := &readline.CompletionGroup{
		Name:         "hosts",
		Descriptions: map[string]string{},
		DisplayType:  readline.TabDisplayList,
	}

	allHosts, err := transport.RPC.Hosts(context.Background(), &commonpb.Empty{})
	if err != nil {
		return
	}
	for _, host := range allHosts.Hosts {
		// Format each Host ID
		var shortID string
		if len(host.HostUUID) < 8 {
			shortID = host.HostUUID[:len(host.HostUUID)]
		} else {
			shortID = host.HostUUID[:8]
		}

		sessions := hosts.HostSessionNumbers(host.HostUUID)
		iocs := strconv.Itoa(len(host.IOCs))

		comp.Suggestions = append(comp.Suggestions, shortID)
		desc := fmt.Sprintf("%s (%s) - %s sessions / %s IOCs", host.Hostname, host.OSVersion, sessions, iocs)
		comp.Descriptions[shortID] = readline.DIM + desc + readline.RESET
	}

	return []*readline.CompletionGroup{comp}
}
