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

	// Transports ------------------------------------------------------------------------------------------

	// The registration might be only to notify us the failure of the very transport that was
	// supposed to be handled here: if the current-was-to-be-switched transport is doing it,
	// simply pass it along in the update function, with its current connection and all transport details.
	// Then return, no need to update any older session/beacon
	var transportID string
	if register.Success {
		transportID = register.TransportID
	} else {
		transportID = register.OldTransportID
	}

	// Get the current target ID for finding its current transports in DB.
	var targetID string
	if session != nil {
		targetID = session.UUID
	} else {
		targetID = beacon.ID.String()
	}

	// And update all the transports related to this target:
	// - If success: mark the new transport as active, the old one inactive.
	// - Update both of their connection strings
	// - Update the others with their respective statistics passed in the registration.
	err = core.UpdateTargetTransports(transportID, targetID, implantConn, register.Session.TransportStats)

	// And query back the updated, current transport
	transport, _ := db.TransportByID(transportID)

	// If the registration switch was not successful,
	// notify users and update the session/beacon state.
	// Otherwise we're ready for updating the session/beacon itself.
	if !register.Success {
		core.CancelTransportSwitch(session, beacon)
		return nil
	}

	// Current => Session ----------------------------------------------------------------------------------
	if transport.Profile.Type == sliverpb.C2Type_Session {

		// If we come from a beacon, we need a new session.
		// If not, we need to update the TLV connection of the
		// current one, otherwise it will stay dry eternally.
		if session == nil {
			session = core.NewSession(implantConn)
		} else {
			session.Connection = implantConn
		}
		// The connection is always assigned a "clean cleanup"
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
