package use

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

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// Use - Interact with a session/beacon
type Use struct {
	Positional struct {
		ID string `description:"session/beacon ID" required:"1-1"` // Name or ID, command will say.
	} `positional-args:"yes" required:"yes"`
}

// Execute - Interact with a session/beacon
func (u *Use) Execute(args []string) (err error) {
	var session *clientpb.Session
	var beacon *clientpb.Beacon
	idArg := u.Positional.ID
	if idArg != "" {
		session, beacon, err = SessionOrBeaconByID(idArg)
	}
	if err != nil {
		return log.Error(err)
	}
	if session != nil {
		core.SetActiveTarget(session, nil)
		log.Infof("Active session %s (%d)", session.Name, session.ID)
	} else if beacon != nil {
		core.SetActiveTarget(nil, beacon)
		log.Infof("Active beacon %s (%s)", beacon.Name, beacon.ID)
	}
	return
}

// SessionOrBeaconByID - Select a session or beacon by ID
func SessionOrBeaconByID(id string) (*clientpb.Session, *clientpb.Beacon, error) {
	sessions, err := transport.RPC.GetSessions(context.Background(), &commonpb.Empty{})
	if err != nil {
		return nil, nil, err
	}
	idNumber, err := strconv.Atoi(id)
	if err == nil {
		for _, session := range sessions.Sessions {
			if session.ID == uint32(idNumber) {
				return session, nil, nil
			}
		}
	}
	beacons, err := transport.RPC.GetBeacons(context.Background(), &commonpb.Empty{})
	if err != nil {
		return nil, nil, err
	}
	for _, beacon := range beacons.Beacons {
		if strings.HasPrefix(beacon.ID, id) {
			return nil, beacon, nil
		}
	}
	return nil, nil, fmt.Errorf("no session or beacon found with ID %s", id)
}
