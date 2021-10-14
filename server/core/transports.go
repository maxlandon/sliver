package core

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
	"fmt"
	"strconv"

	"github.com/gofrs/uuid"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/db"
	"github.com/bishopfox/sliver/server/db/models"
)

// TransportsByTarget - Get all the transports, compiled or set at runtime, for the entire lifetime of an implant run.
// Runtime transports are queried for the SessionUUID, the beaconID if the session is coming from a transport switch.
func TransportsByTarget(session *Session, beacon *models.Beacon) (transports []*models.Transport, err error) {

	var buildName string
	var currentID string

	if beacon != nil {
		buildName = beacon.Name
		currentID = beacon.ID.String()
	}
	if session != nil {
		buildName = session.Name
		currentID = session.UUID
	}

	// Compile-time transports
	compiled, _ := db.TransportsForBuild(buildName)
	transports = compiled

	// Runtime transports set with the current session/beacon
	runtimeCurrent, err := db.TransportsByTargetID(currentID)
	if err != nil {
		return nil, fmt.Errorf("Failed to get transports for current: %s", err)
	}
	for _, runtime := range runtimeCurrent {
		included := false
		for _, found := range transports {
			if found.ID == runtime.ID {
				included = true
				break
			}
		}
		if !included && runtime.ImplantBuildID == uuid.Nil {
			transports = append(transports, runtime)
		}
	}

	return
}

// UpdateTargetTransports - Update all transports of a session/beacon when it registers/switches, passing in
// statistics sent back with the registration. Parameters:
// @newTransportID - The ID of the transport passed in a register/registerSwitch message.
// @targetID       - The ID of the session, beacon that is either registered or switching.
// @conn           - An optional existing implant (logical,TLV) connection to use for populating live rAddr/lAddr
// @stats          - Statistics for all transports loaded on a target, sent by it when registering.
func UpdateTargetTransports(newTransportID, targetID string, conn *Connection, stats []*sliverpb.Transport) (err error) {

	// For each registered transport, including the active one
	for _, registerTransport := range stats {

		// Find in DB
		saved, err := db.TransportByID(registerTransport.ID)
		if err != nil {
			sessionsLog.Errorf("(Transport update) Failed to find transport %s", registerTransport.ID)
			continue
		}
		saved.SessionID = uuid.FromStringOrNil(targetID)

		// If the active one, update it with runtime information from its connection
		if saved.ID.String() == newTransportID {
			_, err = CreateOrUpdateTransport(saved, conn, registerTransport)
			if err != nil {
				sessionsLog.Errorf("Failed to update old Transport: %s", err)
			}
			continue
		}

		// Else, if others, update them with their statistics.
		_, err = CreateOrUpdateTransport(saved, nil, registerTransport)
		if err != nil {
			sessionsLog.Errorf("Failed to update old Transport: %s", err)
		}
	}

	// Get all transports found for this target ID, and remove all that are not
	// present in the register list: this means they are orphaned.
	allTransports, err := db.TransportsByTargetID(targetID)
	if err != nil {
		sessionsLog.Errorf("(Cleanup) Failed to get all target transports: %s", err)
	}

	for _, transport := range allTransports {
		found := false

		for _, runtime := range stats {
			if runtime.ID == transport.ID.String() {
				found = true
				break
			}
		}
		if !found {
			err = db.Session().Delete(transport).Error
			if err != nil {
				sessionsLog.Errorf("Failed to delete transport from DB: %s", err)
			}
		}
	}

	return
}

// CreateOrUpdateTransport - Updates the complete state of a transport, depending
// on its reported status as well as on its profile information.  A nil ImplantConnection
// parameter means the transport is now dead, so the update is made correspondingly.
// A non-nil stats Transport parameter means we have to update the attempts/failures sent by an implant.
func CreateOrUpdateTransport(transport *models.Transport, conn *Connection, stats *sliverpb.Transport) (err, updateErr error) {
	var lAddr string
	var rAddr string

	// If transport is inactive, fill with the profile target information
	if conn == nil {
		transport.Running = false
		if transport.Profile.Direction == sliverpb.C2Direction_Bind {
			lAddr = ""
			rAddr = transport.Profile.Hostname + ":" + strconv.Itoa(int(transport.Profile.Port))
		} else {
			lAddr = transport.Profile.Hostname + ":" + strconv.Itoa(int(transport.Profile.Port)) + transport.Profile.Path
			rAddr = ""
		}
	}

	// If transport is active, fill with the connection information
	if conn != nil {
		transport.Running = true
		lAddr = conn.LocalAddress
		rAddr = conn.RemoteAddress
	}

	// If information was passed by an implant at register/switch time
	if stats != nil {
		transport.Running = stats.Running
		transport.Priority = stats.Order
		transport.Attempts = stats.Attempts
		transport.Failures = stats.Failures
	}

	// Assign and save
	transport.LocalAddress = lAddr
	transport.RemoteAddress = rAddr
	updateErr = db.Session().Save(transport).Error

	return
}

// CleanupTargetTransports - Once a session has been killed (and not merely disconnected)
// delete all the transports that have been set at runtime, so that they don't pile up at
// each new session reconnection/restart.
func CleanupTargetTransports(sess *Session) (err error) {

	// Get the transports (runtime and build) for the session
	transports, err := TransportsByTarget(sess, nil)
	if err != nil {
		return fmt.Errorf("Failed to retrieve session transports: %s", err)
	}
	build, err := db.ImplantBuildByName(sess.Name)
	if err != nil {
		return fmt.Errorf("Failed to retrieve session implant build: %s", err)
	}

	// Diff both lists of transports
	var toDelete = []*models.Transport{}
	for _, transport := range transports {

		// And save the updated values while at it:
		transport.Running = false
		found := false
		if transport.Profile.Direction == sliverpb.C2Direction_Bind {
			transport.LocalAddress = ""
		} else {
			transport.RemoteAddress = ""
		}
		err = db.Session().Save(&transport).Error
		if err != nil {
			sessionsLog.Errorf("failed to update transport running status")
		}

		// And finally filter by build ID
		for _, buildTransport := range build.Transports {
			if buildTransport.ID == transport.ID {
				found = true
				break
			}
		}
		if !found {
			toDelete = append(toDelete, transport)
		}
	}

	// And delete those that have been set at runtime
	for _, transport := range toDelete {
		err = db.Session().Delete(transport).Error
		if err != nil {
			sessionsLog.Errorf("Failed to delete transport from DB: %s", err)
		}
	}

	return
}

// CleanupOrphanedTransports - This function is ran at every server startup:
// It deletes all transports that:
// - Have no implant build ID, thus are not runtime one, except those for which
// the session ID is a valid beacon ID (the beacon might still be alive).
func CleanupOrphanedTransports() (err error) {

	allTransports, err := db.AllTransports()
	if err != nil {
		return fmt.Errorf("failed to get all transports: %s", err)
	}

	// For each of them
	for _, transport := range allTransports {

		// If there is an implant build, it's compiled, we keep it and
		// reset the running value to false: will be reset when connecting.
		if transport.ImplantBuildID != uuid.Nil {
			transport.Running = false
			if transport.Profile.Direction == sliverpb.C2Direction_Bind {
				transport.LocalAddress = ""
			} else {
				transport.RemoteAddress = ""
			}
			err = db.Session().Save(transport).Error
			if err != nil {
				sessionsLog.Errorf("failed to update transport running status")
			}
			continue
		}

		// If the session ID is a valid beacon ID, keep it as well
		beacon, err := db.BeaconByID(transport.SessionID.String())
		if err == nil && beacon.ID != uuid.Nil {
			continue
		}

		// Else we delete the transport
		err = db.Session().Delete(transport).Error
		if err != nil {
			sessionsLog.Errorf("failed to delete transport %s", transport.ID)
		}
	}

	return
}

// RegisterTransportSwitch - A session wants to switch its current transport, mark it
// accordingly so that the session is not deregistered upon connection closing.
func RegisterTransportSwitch(sess *Session, beacon *models.Beacon) (err error) {

	if sess != nil {
		if sess.State == clientpb.State_Switching.String() {
			return fmt.Errorf("Session %d (%s) is currently switching its transport",
				sess.ID, sess.HostUUID)
		}

		delete(Sessions.sessions, sess.ID)
		sess.State = clientpb.State_Switching.String()
		Sessions.UpdateSession(sess)
	}

	if beacon != nil {
		if beacon.State == clientpb.State_Switching.String() {
			return fmt.Errorf("Beacon %s (%s) is currently switching its transport",
				GetShortID(beacon.ID.String()), beacon.HostUUID)
		}

		beacon.State = clientpb.State_Switching.String()
		_, err = db.UpdateOrCreateBeacon(beacon)
		EventBroker.Publish(Event{
			Type:   clientpb.EventType_BeaconUpdated,
			Beacon: beacon,
		})
	}

	return
}

// GetTargetSwitching - When sending the registration message following the transport
// switch, the session/beacon has provided the ID of its old transport, which should
// be unique among all sessions/beacons. Find it and return it for update.
func GetTargetSwitching(oldTransportID string) (sess *Session, beacon *models.Beacon) {
	for _, s := range Sessions.All() {
		if s.State == clientpb.State_Switching.String() && s.Transport.ID.String() == oldTransportID {
			return s, nil
		}
	}
	beacons, _ := db.ListBeacons()
	for _, b := range beacons {
		if b.State == clientpb.State_Switching.String() && b.TransportID == oldTransportID {
			return nil, b
		}
	}

	return
}
