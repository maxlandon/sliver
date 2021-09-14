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

// Interact - Interact with a Sliver implant. This commands changes the console
// context, with different commands and completions.
type Interact struct {
	Positional struct {
		SessionID string `description:"session ID" required:"1-1"` // Name or ID, command will say.
	} `positional-args:"yes" required:"yes"`
}

// Execute - Interact with a Sliver implant.
func (i *Interact) Execute(args []string) (err error) {

	session, err := getSession(i.Positional.SessionID)
	if err != nil {
		return log.Error(err)
	}
	if session != nil {
		core.SetActiveSession(session)
		log.Infof("Active session %s (%d)\n", session.Name, session.ID)
	}

	return
}

func getSession(arg string) (sess *clientpb.Session, err error) {
	sessions, err := transport.RPC.GetSessions(context.Background(), &commonpb.Empty{})
	if err != nil {
		return nil, log.Error(err)
	}
	for _, session := range sessions.GetSessions() {
		if fmt.Sprintf("%d", session.ID) == arg {
			return session, nil
		}
	}
	return nil, log.Errorf("Invalid session name or session number '%s'", arg)
}
