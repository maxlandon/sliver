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
	"github.com/gofrs/uuid"
)

// registerTransportSwitch - The implant has established a new connection to the server and sent
// a registration notifying this new transport. Updates the session transport details.
func registerTransportSwitchHandler(conn *core.Connection, data []byte) *sliverpb.Envelope {
	if conn == nil {
		return nil
	}
	reg := &sliverpb.RegisterTransportSwitch{}
	err := proto.Unmarshal(data, reg)
	if err != nil {
		sessionHandlerLog.Errorf("Error decoding session registration message: %s", err)
		return nil
	}

	// Find the session/beacon matching the details sent in the request.
	session, beacon, targetID := core.GetTargetSwitching(reg.OldTransportID)
	if session == nil && beacon == nil {
		sessionHandlerLog.Errorf("(Transport switch) Failed to find session for transport %s", reg.OldTransportID)
		return nil
	}

	// Transports ------------------------------------------------------------------------------------------

	// And query back the updated, current transport
	transport, _ := db.TransportByID(reg.TransportID)

	// The registration might be only to notify us the failure of the very transport that was
	// supposed to be handled here: if the current-was-to-be-switched transport is doing it,
	// simply pass it along in the update function, with its current connection and all transport details.
	// Then return, no need to update any older session/beacon
	if !reg.Success {

		// Update all the transports related to this target:
		err = core.UpdateTargetTransports(reg.TransportID, targetID, conn, reg.Session.TransportStats)

		// Notify users and update the session/beacon state.
		core.CancelTransportSwitch(session, beacon)
		return nil
	}

	// Current => Session ----------------------------------------------------------------------------------
	if transport.Profile.Type == sliverpb.C2Type_Session {

		// If we come from a beacon, we need a new session.
		// If not, we need to update the TLV connection of the
		// current one, otherwise it will stay dry eternally.
		if session == nil {
			session = core.NewSession(conn)
		} else {
			session.Connection = conn
		}
		session.UUID = reg.Session.UUID
		// The connection is always assigned a "clean cleanup"
		conn.Cleanup = func() {
			core.Sessions.Remove(session.ID)
		}

		// And update all the transports current loaded on this target, and use the updated current the session
		err = core.UpdateTargetTransports(reg.TransportID, session.UUID, conn, reg.Session.TransportStats)
		session.Transport, _ = db.TransportByID(reg.TransportID)

		// And handle switch registration
		err = switchSession(session, beacon, reg.Session)
		if err != nil {
			sessionHandlerLog.Errorf("(Transport switch => session) Failed with error: %s", err)
		}
	}

	// Current => Beacon ----------------------------------------------------------------------------------
	if transport.Profile.Type == sliverpb.C2Type_Beacon {

		// Get beacon if existing, or instantiate a new one and assign
		// its ID (needed for updating/linking its transports now).
		beacon, err := db.BeaconByID(reg.Beacon.ID)
		beaconHandlerLog.Debugf("Found %v err = %s", beacon, err)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			beaconHandlerLog.Errorf("Database query error %s", err)
			return nil
		}
		beacon.ID = uuid.FromStringOrNil(reg.Beacon.ID)

		// And update all the transports current loaded on this target, and use the updated current for the beacon.
		err = core.UpdateTargetTransports(reg.TransportID, beacon.ID.String(), conn, reg.Session.TransportStats)
		beacon.Transport, _ = db.TransportByID(reg.TransportID)

		// And handle switch registration
		err = switchBeacon(beacon, session, reg, conn)
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
