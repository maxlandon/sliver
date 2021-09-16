package sessions

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
	"strconv"

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/client/util"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// Main & Sliver context available commands
// ----------------------------------------------------------------------------------------------------------

// Sessions - Root command for managing sessions. Prints registered sessions by default.
type Sessions struct{}

// Execute - Prints registered sessions if no sub commands invoked.
func (s *Sessions) Execute(args []string) (err error) {

	// Get a map of all sessions
	sessions, err := transport.RPC.GetSessions(context.Background(), &commonpb.Empty{})
	if err != nil {
		return log.Error(err)
	}
	sessionsMap := map[uint32]*clientpb.Session{}
	for _, session := range sessions.GetSessions() {
		sessionsMap[session.ID] = session
	}

	// Print all sessions
	if 0 < len(sessionsMap) {
		printSessions(sessionsMap)
	} else {
		log.Infof("No sessions")
	}

	return
}

func printSessions(sessions map[uint32]*clientpb.Session) {

	// Sort keys
	var keys []int
	for k := range sessions {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)

	table := util.NewTable("")
	headers := []string{"ID", "Name", "OS/Arch", "Remote Address", "User", "Hostname", "Last Check-in", "Status"}
	headLen := []int{0, 0, 0, 15, 0, 0, 0, 0}
	table.SetColumns(headers, headLen)

	for _, k := range keys {
		s := sessions[uint32(k)]
		osArch := fmt.Sprintf("%s/%s", s.OS, s.Arch)

		var status string
		if s.IsDead {
			status = "Dead"
		} else {
			status = "Alive"
		}
		burned := ""
		if s.Burned {
			burned = "🔥"
		}
		row := []string{strconv.Itoa(int(s.ID)), s.Name, osArch, s.RemoteAddress, s.Username,
			s.Hostname, strconv.Itoa(int(s.LastCheckin)), burned + status}

		table.AppendRow(row)
	}
	table.Output()
}
