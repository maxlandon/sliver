package handlers

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
	"google.golang.org/protobuf/proto"

	sliverpb "github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/db"
)

// registerTransportSwitch - The implant has established a new connection to the server and sent
// a registration notifying this new transport. Updates the session transport details.
func registerTransportSwitchHandler(implantConn *core.ImplantConnection, data []byte) *sliverpb.Envelope {
	if implantConn == nil {
		return nil
	}
	register := &sliverpb.RegisterTransportSwitch{}
	err := proto.Unmarshal(data, register)
	if err != nil {
		sessionHandlerLog.Errorf("Error decoding session registration message: %s", err)
		return nil
	}

	// Find the session/beacon matching the details sent in the request.
	session, beacon := core.GetTargetSwitching(register.OldTransportID)
	if session == nil && beacon == nil {
		sessionHandlerLog.Errorf("(Transport switch) Failed to find session for transport %s", register.OldTransportID)
		return nil
	}
	var buildName string
	if session != nil {
		buildName = session.Name
	} else {
		buildName = beacon.Name
	}

	// Get this new transport and implant build
	build, err := db.ImplantBuildByName(buildName)
	transport, err := db.TransportByID(register.TransportID)
	if transport == nil || err != nil {
		sessionHandlerLog.Errorf("(Transport switch) Failed to find transport %s", register.TransportID)
		return nil
	}

	// Update the old transport
	oldTransport, err := db.TransportByID(register.OldTransportID)
	if err != nil {
		sessionHandlerLog.Errorf("(Transport switch) Failed to find old transport %s", register.OldTransportID)
	}
	oldTransport.Running = false
	err = db.Session().Save(&oldTransport).Error
	if err != nil {
		sessionHandlerLog.Errorf("Failed to update Transport status: %s", err)
	}

	// Current => Session ----------------------------------------------------------------------------------
	if transport.Profile.Type == sliverpb.C2Type_Session {

		// We might come from a beacon, so we might need a new session
		if session == nil {
			session = core.NewSession(implantConn)
			implantConn.Cleanup = func() {
				core.Sessions.Remove(session.ID)
			}
		}

		// But we have its new transport anyway
		session.Transport = transport

		err = switchSession(session, beacon, register.Session, build)
		if err != nil {
			sessionHandlerLog.Errorf("(Transport switch => session) Failed with error: %s", err)
		}
	}

	// Current => Beacon ----------------------------------------------------------------------------------
	if transport.Profile.Type == sliverpb.C2Type_Beacon {
		err = switchBeacon(session, register, implantConn, transport)
		if err != nil {
			sessionHandlerLog.Errorf("(Transport switch => beacon) Failed with error: %s", err)
		}

		// If we were a session, close the session and publish
		if session != nil {
			core.Sessions.RemoveSwitched(session.ID)
		}

	}

	return nil
}
