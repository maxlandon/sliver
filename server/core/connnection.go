package core

/*
	Sliver Implant Framework
	Copyright (C) 2021  Bishop Fox

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
	"sync"
	"time"

	"github.com/gofrs/uuid"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/db"
	"github.com/bishopfox/sliver/server/db/models"
)

func init() {
	// Always cleanup all transports that are not compiled in a build
	// and do not have a valid beacon ID (the beacon might be rolling still)
	CleanupOrphanedTransports()
}

// ImplantConnection - Implementation of a logical connection system around
// a C2 channel (whether net.Conn based or not). This object is neither a
// pure net.Conn implementation neither an idiomatic RPC system, but halfway both.
type ImplantConnection struct {
	ID            string
	Send          chan *sliverpb.Envelope
	RespMutex     *sync.RWMutex
	Resp          map[int64]chan *sliverpb.Envelope
	Transport     string
	RemoteAddress string
	LastMessage   time.Time
	Cleanup       func()
}

// UpdateLastMessage - Update the time at which the session sent its last message.
func (c *ImplantConnection) UpdateLastMessage() {
	c.LastMessage = time.Now()
}

// NewImplantConnection - A physical connection needs to be wrapped into a Session connection.
func NewImplantConnection(transport string, remoteAddress string) *ImplantConnection {
	return &ImplantConnection{
		ID:            generateImplantConnectionID(),
		Send:          make(chan *sliverpb.Envelope, 100),
		RespMutex:     &sync.RWMutex{},
		Resp:          map[int64]chan *sliverpb.Envelope{},
		Transport:     transport,
		RemoteAddress: remoteAddress,
		Cleanup:       func() {},
	}
}

func generateImplantConnectionID() string {
	id, _ := uuid.NewV4()
	return id.String()
}

// RegisterTransportSwitch - A session wants to switch its current transport, mark it
// accordingly so that the session is not deregistered upon connection closing.
func RegisterTransportSwitch(sess *Session, beacon *models.Beacon) (err error) {

	if sess != nil {
		if sess.State == clientpb.State_Switching {
			return fmt.Errorf("Session %d (%s) is currently switching its transport",
				sess.ID, sess.HostUUID)
		}

		// Else update its state and publish
		delete(Sessions.sessions, sess.ID)
		sess.State = clientpb.State_Switching
		Sessions.UpdateSession(sess)
	}

	if beacon != nil {
		if beacon.State == clientpb.State_Switching {
			return fmt.Errorf("Beacon %s (%s) is currently switching its transport",
				GetShortID(beacon.ID.String()), beacon.HostUUID)
		}

		beacon.State = clientpb.State_Switching
		db.Session().Save(&beacon)
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
		if s.State == clientpb.State_Switching && s.Transport.ID.String() == oldTransportID {
			return s, nil
		}
	}
	beacons, _ := db.ListBeacons()
	for _, b := range beacons {
		if b.State == clientpb.State_Switching && b.TransportID == oldTransportID {
			return nil, b
		}
	}

	return
}

// TransportsByTarget - Get all the transports, compiled or set at runtime, for the entire lifetime of an implant run.
// Runtime transports are queried for the SessionUUID, the beaconID if the session is coming from a transport switch.
func TransportsByTarget(session *Session, beacon *models.Beacon) (transports []*models.Transport, err error) {

	var buildName string

	if beacon != nil {
		buildName = beacon.Name
		compiled, _ := db.TransportsForBuild(buildName)
		transports = append(transports, compiled...)

		// Get any runtime transports set when we were a session, if we were
		if beacon.SessionID != "" {
			runtime, err := db.TransportsBySession(beacon.SessionID)
			if err != nil {
				return nil, fmt.Errorf("Failed to get transports for beacon: %s", err)
			}
			for _, t := range runtime {
				if t.ImplantBuildID == uuid.Nil {
					transports = append(transports, t)
				}
			}
		} else {
			runtime, err := db.TransportsBySession(beacon.ID.String())
			if err != nil {
				return nil, fmt.Errorf("Failed to get transports for beacon: %s", err)
			}
			for _, t := range runtime {
				if t.ImplantBuildID == uuid.Nil {
					transports = append(transports, t)
				}
			}
		}

		return transports, nil
	}

	if session != nil {
		buildName = session.Name
		compiled, _ := db.TransportsForBuild(buildName)
		transports = append(transports, compiled...)

		// Get any runtime transports set when we were a beacon, if we were
		if session.BeaconID != "" {
			runtime, err := db.TransportsBySession(session.BeaconID)
			if err != nil {
				return nil, fmt.Errorf("Failed to get transports for session: %s", err)
			}
			for _, t := range runtime {
				if t.ImplantBuildID == uuid.Nil {
					transports = append(transports, t)
				}
			}
		}

		// Get any runtime transports set by sessions with the same UUID
		// (that is, sessions spawned during the lifetime of this implant run)
		runtime, err := db.TransportsBySession(session.UUID)
		if err != nil {
			return nil, fmt.Errorf("Failed to get transports for session: %s", err)
		}
		for _, t := range runtime {
			if t.ImplantBuildID == uuid.Nil {
				transports = append(transports, t)
			}
		}

		return transports, nil
	}

	return
}

// UpdateSessionTransports - When a session registers/switches, it sends stats on all
// of its currently available transports. Update them in DB for clients to see.
func UpdateSessionTransports(transports []*sliverpb.Transport) (err error) {

	for _, t := range transports {
		transport, err := db.TransportByID(t.ID)
		if err != nil || transport == nil {
			sessionsLog.Errorf("Failed to find transport %s", t.ID)
		}

		transport.Priority = t.Order
		transport.Attempts = t.Attempts
		transport.Failures = t.Failures
		transport.Running = t.Running

		err = db.Session().Save(transport).Error
		if err != nil {
			sessionsLog.Errorf("Failed to save transport %s", t.ID)
		}
	}

	return
}

// CleanupSessionTransports - Once a session has been killed (and not merely disconnected)
// delete all the transports that have been set at runtime, so that they don't pile up at
// each new session reconnection/restart.
func CleanupSessionTransports(sess *Session) (err error) {

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
		found := false
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

	allTransports := []*models.Transport{}
	err = db.Session().Find(&allTransports).Error
	if err != nil {
		return fmt.Errorf("failed to get all transports: %s", err)
	}

	// For each of them
	for _, transport := range allTransports {

		// If there is an implant build, it's compiled, we keep it and
		// reset the running value to false: will be reset when connecting.
		if transport.ImplantBuildID != uuid.Nil {
			transport.Running = false
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
