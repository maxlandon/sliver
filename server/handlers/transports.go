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
	"errors"

	"google.golang.org/protobuf/proto"
	"gorm.io/gorm"

	sliverpb "github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/db"
)

// registerTransportSwitch - The implant has established a new connection to the server and sent
// a registration notifying this new transport. Updates the session transport details.
func registerTransportSwitchHandler(implantConn *core.Connection, data []byte) *sliverpb.Envelope {
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
	// if session != nil {
	//         fmt.Println("Session NOT NIL")
	// }
	// if beacon != nil {
	//         fmt.Println("Beacon NOT NIL")
	// }

	// Transports ------------------------------------------------------------------------------------------

	// First get the new transport updated, we need it for info
	transport, err := db.TransportByID(register.TransportID)
	if transport == nil || err != nil {
		sessionHandlerLog.Errorf("(Transport update) Failed to find transport %s", register.TransportID)
		return nil
	}

	// Get runtime statistics for all transports
	var targetID string
	if session != nil {
		targetID = session.UUID
	} else {
		targetID = beacon.ID.String()
	}

	var stats []*sliverpb.Transport
	switch transport.Profile.Type {
	case sliverpb.C2Type_Session:
		stats = register.Session.TransportStats
	case sliverpb.C2Type_Beacon:
		stats = register.Beacon.Register.TransportStats
	}

	// Update all the transports related to this target:
	// - mark the old one as inactive
	// - mark the new one as active, and format its live connection string
	// - Update the others with their respective statistics passed in the registration.
	err = core.UpdateTargetTransports(register.TransportID, targetID, implantConn, stats)

	// And query the updated transport, otherwise we use the wrong copy
	transport, _ = db.TransportByID(transport.ID.String())

	// Current => Session ----------------------------------------------------------------------------------
	if transport.Profile.Type == sliverpb.C2Type_Session {

		// We might come from a beacon, so we might need a new session
		if session == nil {
			session = core.NewSession(implantConn)
		} else {
			session.Connection = implantConn
		}
		implantConn.Cleanup = func() {
			core.Sessions.Remove(session.ID)
		}
		session.Transport = transport

		// And handle switch registration
		err = switchSession(session, beacon, register.Session)
		if err != nil {
			sessionHandlerLog.Errorf("(Transport switch => session) Failed with error: %s", err)
		}
	}

	// Current => Beacon ----------------------------------------------------------------------------------
	if transport.Profile.Type == sliverpb.C2Type_Beacon {

		// Get beacon if existing, or instantiate a new one
		beacon, err := db.BeaconByID(register.Beacon.ID)
		beaconHandlerLog.Debugf("Found %v err = %s", beacon, err)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			beaconHandlerLog.Errorf("Database query error %s", err)
			return nil
		}
		beacon.Transport = transport

		// And handle switch registration
		err = switchBeacon(beacon, session, register.Beacon, implantConn)
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
