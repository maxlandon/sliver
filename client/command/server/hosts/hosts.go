package hosts

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
	"strings"

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/client/util"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// Hosts - Manage the database of hosts
type Hosts struct{}

// Execute - Manage the database of hosts
func (h *Hosts) Execute(args []string) (err error) {
	allHosts, err := transport.RPC.Hosts(context.Background(), &commonpb.Empty{})
	if err != nil {
		return log.Error(err)
	}
	if 0 < len(allHosts.Hosts) {
		displayHosts(allHosts.Hosts)
	} else {
		log.Infof("No hosts")
	}
	return
}

func displayHosts(hosts []*clientpb.Host) {

	table := util.NewTable("")
	headers := []string{"ID", "Hostname", "Operating System", "Sessions", "IOCs", "Extension Data"}
	headLen := []int{0, 0, 0, 0, 0, 0}
	table.SetColumns(headers, headLen)

	for _, host := range hosts {
		var shortID string
		if len(host.HostUUID) < 8 {
			shortID = host.HostUUID[:len(host.HostUUID)]
		} else {
			shortID = host.HostUUID[:8]
		}
		sessions := HostSessionNumbers(host.HostUUID)
		iocs := strconv.Itoa(len(host.IOCs))
		extData := strconv.Itoa(len(host.ExtensionData))

		table.AppendRow([]string{shortID, host.Hostname, host.OSVersion, sessions, iocs, extData})
	}

	fmt.Printf(table.Output())
}

// HostSessionNumbers - Format the number of sessions for a host
func HostSessionNumbers(hostUUID string) string {
	hostSessions := SessionsForHost(hostUUID)
	if 0 == len(hostSessions) {
		return "None"
	}
	sessionNumbers := []string{}
	for _, hostSession := range hostSessions {
		sessionNumbers = append(sessionNumbers, fmt.Sprintf("%d", hostSession.ID))
	}
	return strings.Join(sessionNumbers, ", ")
}

// SessionsForHost - Find sessions for a given host by id
func SessionsForHost(hostUUID string) []*clientpb.Session {
	sessions, err := transport.RPC.GetSessions(context.Background(), &commonpb.Empty{})
	if err != nil {
		return []*clientpb.Session{}
	}
	hostSessions := []*clientpb.Session{}
	for _, session := range sessions.Sessions {
		if session.HostUUID == hostUUID {
			hostSessions = append(hostSessions, session)
		}
	}
	return hostSessions
}
