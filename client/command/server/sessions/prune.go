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

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// SessionsClean - Clean sessions marked dead
type SessionsClean struct{}

// Execute - Clean sessions marked dead
func (ka *SessionsClean) Execute(args []string) (err error) {

	// Get a map of all sessions
	sessions, err := transport.RPC.GetSessions(context.Background(), &commonpb.Empty{})
	if err != nil {
		return log.Error(err)
	}
	sessionsMap := map[uint32]*clientpb.Session{}
	for _, session := range sessions.GetSessions() {
		sessionsMap[session.ID] = session
	}
	if len(sessionsMap) == 0 {
		log.Infof("No sessions \n")
		return
	}

	// Kill all IDs
	for i := range sessionsMap {
		sess, ok := sessionsMap[i]
		if !ok || sess == nil {
			err := log.Errorf("Invalid session ID: %d\n", i)
			if err != nil {
				fmt.Printf(err.Error())
			}
		}

		if sess.IsDead {
			// Kill session
			err = killSession(sess, true, transport.RPC)
			if err != nil {
				fmt.Printf(err.Error())
			}

			// Change context if we are killing the current session
			active := core.ActiveTarget.Session()
			if active != nil && sess.ID == active.ID {
				core.UnsetActiveSession()
			}
		}
	}

	return
}
