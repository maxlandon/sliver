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
	------------------------------------------------------------------------

	WARNING: These functions can be invoked by remote implants without user interaction

*/

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	gofrsUuid "github.com/gofrs/uuid"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"gorm.io/gorm"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/comm"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/db"
	"github.com/bishopfox/sliver/server/db/models"
	"github.com/bishopfox/sliver/server/log"
)

var (
	sessionHandlerLog = log.NamedLogger("handlers", "sessions")
)

func registerSessionHandler(implantConn *core.ImplantConnection, data []byte) *sliverpb.Envelope {
	if implantConn == nil {
		return nil
	}
	register := &sliverpb.Register{}
	err := proto.Unmarshal(data, register)
	if err != nil {
		sessionHandlerLog.Errorf("Error decoding session registration message: %s", err)
		return nil
	}

	session := core.NewSession(implantConn)

	// Parse Register UUID
	hostUUID, err := uuid.Parse(register.HostUUID)
	if err != nil {
		hostUUID = uuid.New() // Generate Random UUID
	}
	session.UUID = register.UUID
	session.Name = register.Name
	session.Hostname = register.Hostname
	session.HostUUID = hostUUID.String()
	session.Username = register.Username
	session.UID = register.Uid
	session.GID = register.Gid
	session.Os = register.Os
	session.Arch = register.Arch
	session.PID = register.Pid
	session.Filename = register.Filename
	session.ActiveC2 = register.ActiveC2
	session.Version = register.Version
	session.ReconnectInterval = register.ReconnectInterval
	session.PollTimeout = register.PollTimeout
	session.ProxyURL = register.ProxyURL
	session.ConfigID = register.ConfigID
	session.WorkingDirectory = register.WorkingDirectory
	session.State = clientpb.State_Alive

	core.Sessions.Add(session)
	implantConn.Cleanup = func() {
		core.Sessions.Remove(session.ID)
	}
	go auditLogSession(session, register)

	// Finally, set up the Comm subsystem if the transport requires it.
	err = SetSessionCommSubsystem(register.TransportID, session)
	if err != nil {
		sessionHandlerLog.Errorf(err.Error())
	}

	// Start any persistent jobs that might exist for this precise session
	err = core.StartPersistentSessionJobs(session)
	if err != nil {
		sessionHandlerLog.Errorf("failed to start persistent jobs: %s", err)
	}

	return nil
}

type auditLogNewSessionMsg struct {
	Session  *clientpb.Session
	Register *sliverpb.Register
}

func auditLogSession(session *core.Session, register *sliverpb.Register) {
	msg, err := json.Marshal(auditLogNewSessionMsg{
		Session:  session.ToProtobuf(),
		Register: register,
	})
	if err != nil {
		sessionHandlerLog.Errorf("Failed to log new session to audit log %s", err)
	} else {
		log.AuditLogger.Warn(string(msg))
	}
}

// SetSessionCommSubsystem - Based on the transport C2 profile and the build information,
// set up the SSH-based Comm subsystem. This rests on a single Tunnel used on top of the Connection.
func SetSessionCommSubsystem(transportID string, session *core.Session) (err error) {

	// Add protocol, network and route-adjusted address fields
	uri, _ := url.Parse(session.ActiveC2)       // TODO: change this, might be wrong with pivot sessions
	session.RemoteAddress = uri.Host + uri.Path // Set the non-resolved routed address first
	session.RemoteAddress = comm.SetCommString(session)

	// Get the current transport used by the Session
	transport, err := db.TransportByID(transportID)
	if transport == nil {
		return fmt.Errorf("Could not find transport with ID %s", transportID)
	}
	session.TransportID = transport.ID.String()

	// Save the transport as running
	transport.Running = true
	transport.SessionID = gofrsUuid.FromStringOrNil(session.UUID)
	err = db.Session().Save(&transport).Error
	if err != nil {
		return fmt.Errorf("Failed to update Transport: %s", err)
	}

	// If this transport specifically asks not to be Comm wired, or if the
	// implant build forbids it anyway, just return, we have nothing to set up.
	build, err := db.ImplantBuildByName(session.Name)
	if build == nil || err != nil {
		return fmt.Errorf("Could not find implant build: %s", err)
	}
	if transport.Profile.CommDisabled || !build.ImplantConfig.CommEnabled {
		return
	}

	// Instantiate and start the Comms, which will build a Tunnel over the Session RPC.
	err = comm.InitSession(session)
	if err != nil {
		sessionHandlerLog.Errorf("Comm init failed: %v", err)
		return
	}

	return
}

// The handler mutex prevents a send on a closed channel, without it
// two handlers calls may race when a tunnel is quickly created and closed.
func tunnelDataHandler(implantConn *core.ImplantConnection, data []byte) *sliverpb.Envelope {
	session := core.SessionFromImplantConnection(implantConn)
	tunnelHandlerMutex.Lock()
	defer tunnelHandlerMutex.Unlock()
	tunnelData := &sliverpb.TunnelData{}
	proto.Unmarshal(data, tunnelData)
	tunnel := core.Tunnels.Get(tunnelData.TunnelID)
	if tunnel != nil {
		if session.ID == tunnel.SessionID {
			tunnel.FromImplant <- tunnelData
		} else {
			sessionHandlerLog.Warnf("Warning: Session %d attempted to send data on tunnel it did not own", session.ID)
		}
	} else {
		sessionHandlerLog.Warnf("Data sent on nil tunnel %d", tunnelData.TunnelID)
	}
	return nil
}

func tunnelCloseHandler(implantConn *core.ImplantConnection, data []byte) *sliverpb.Envelope {
	session := core.SessionFromImplantConnection(implantConn)
	tunnelHandlerMutex.Lock()
	defer tunnelHandlerMutex.Unlock()

	tunnelData := &sliverpb.TunnelData{}
	proto.Unmarshal(data, tunnelData)
	if !tunnelData.Closed {
		return nil
	}
	tunnel := core.Tunnels.Get(tunnelData.TunnelID)
	if tunnel != nil {
		if session.ID == tunnel.SessionID {
			sessionHandlerLog.Infof("Closing tunnel %d", tunnel.ID)
			core.Tunnels.Close(tunnel.ID)
		} else {
			sessionHandlerLog.Warnf("Warning: Session %d attempted to send data on tunnel it did not own", session.ID)
		}
	} else {
		sessionHandlerLog.Warnf("Close sent on nil tunnel %d", tunnelData.TunnelID)
	}
	return nil
}

func pingHandler(implantConn *core.ImplantConnection, data []byte) *sliverpb.Envelope {
	session := core.SessionFromImplantConnection(implantConn)
	sessionHandlerLog.Debugf("ping from session %d", session.ID)
	return nil
}

// commTunnelDataHandler - Handle Comm tunnel data coming from the server.
func commTunnelDataHandler(conn *core.ImplantConnection, data []byte) *sliverpb.Envelope {
	session := core.SessionFromImplantConnection(conn)
	tunnelData := &commpb.TunnelData{}
	proto.Unmarshal(data, tunnelData)
	tunnel := comm.Tunnels.Tunnel(tunnelData.TunnelID)
	if tunnel != nil {
		sessionHandlerLog.Infof("Found tunnel")
		if session.ID == tunnel.Sess.ID {
			sessionHandlerLog.Infof("Found tunnel for session")
			tunnel.FromImplant <- tunnelData
		} else {
			sessionHandlerLog.Warnf("Warning: Session %d attempted to send data on tunnel it did not own", session.ID)
		}
	} else {
		sessionHandlerLog.Warnf("Data sent on nil tunnel %d", tunnelData.TunnelID)
	}
	return nil
}

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

	// Switch to Session if the current C2 transport is a session
	if transport.Profile.Type == sliverpb.C2Type_Session {
		err = switchSession(session, beacon, register, implantConn, transport, build)
		if err != nil {
			sessionHandlerLog.Errorf("(Transport switch => session) Failed with error: %s", err)
		}
	}

	// Or to a beacon otherwise
	if transport.Profile.Type == sliverpb.C2Type_Beacon {
		err = switchBeacon(session, register, implantConn, transport)
		if err != nil {
			sessionHandlerLog.Errorf("(Transport switch => beacon) Failed with error: %s", err)
		}
	}

	return nil
}

// switchSession - Create a session if the current target was a beacon, or update the session if it was already one.
func switchSession(s *core.Session, bc *models.Beacon, r *sliverpb.RegisterTransportSwitch, c *core.ImplantConnection, t *models.Transport, b *models.ImplantBuild) error {

	var sessionExists = false
	if s != nil {
		s = core.NewSession(c)
	} else {
		sessionExists = true
	}

	// Parse Register UUID
	hostUUID, err := uuid.Parse(r.Session.HostUUID)
	if err != nil {
		hostUUID = uuid.New() // Generate Random UUID
	}
	s.UUID = r.Session.UUID
	s.Name = r.Session.Name
	s.Hostname = r.Session.Hostname
	s.HostUUID = hostUUID.String()
	s.Username = r.Session.Username
	s.UID = r.Session.Uid
	s.GID = r.Session.Gid
	s.Os = r.Session.Os
	s.Arch = r.Session.Arch
	s.PID = r.Session.Pid
	s.Filename = r.Session.Filename
	s.ActiveC2 = r.Session.ActiveC2
	s.Version = r.Session.Version
	s.ReconnectInterval = r.Session.ReconnectInterval
	s.PollTimeout = r.Session.PollTimeout
	s.ProxyURL = r.Session.ProxyURL
	s.ConfigID = r.Session.ConfigID
	s.WorkingDirectory = r.Session.WorkingDirectory
	s.State = clientpb.State_Alive
	if bc != nil {
		s.BeaconID = bc.ID.String() // Switching from a beacon
	}

	// Add protocol, network and route-adjusted address fields
	uri, _ := url.Parse(s.ActiveC2)       // TODO: change this, might be wrong with pivot sessions
	s.RemoteAddress = uri.Host + uri.Path // Set the non-resolved routed address first
	s.RemoteAddress = comm.SetCommString(s)

	// Update the transport and connection details for the session
	s.TransportID = t.ID.String()
	t.Running = true
	t.SessionID = gofrsUuid.FromStringOrNil(s.UUID)
	err = db.Session().Save(&t).Error
	if err != nil {
		sessionHandlerLog.Errorf("Failed to update Transport: %s", err)
		return nil
	}

	// If we were a beacon: add session and update beacon
	if !sessionExists {
		core.Sessions.Add(s)
		c.Cleanup = func() {
			core.Sessions.Remove(s.ID)
		}
		go auditLogSession(s, r.Session)

		// We were a beacon: mark it inactive, so it doesn't
		// show up in some completions, cannot be used, etc
		bc.State = clientpb.State_Disconnect
		db.Session().Save(&bc)
		core.EventBroker.Publish(core.Event{
			Type:   clientpb.EventType_BeaconUpdated,
			Beacon: bc,
		})
	}

	// If we were already a session: just update it
	if sessionExists {
		core.Sessions.UpdateSession(s)
	}

	// If this transport specifically asks not to be Comm wired, or if the
	// implant build forbids it anyway, just return, we have nothing to restart.
	if t.Profile.CommDisabled || !b.ImplantConfig.CommEnabled {
		return nil
	}

	// Restart the Comms if required. TODO: restart active portforwarders/proxies
	err = comm.InitSession(s)
	if err != nil {
		sessionHandlerLog.Errorf("Comm init failed: %v", err)
		return nil
	}

	// Start any persistent jobs that might exist for this precise session
	// err = core.StartPersistentSessionJobs(session)
	// if err != nil {
	//         sessionHandlerLog.Errorf("failed to start persistent jobs: %s", err)
	// }

	return nil
}

// switchBeacon - Create or update a beacon with the registration, and if the previous target was a session, remove it.
func switchBeacon(s *core.Session, reg *sliverpb.RegisterTransportSwitch, conn *core.ImplantConnection, t *models.Transport) error {

	beaconHandlerLog.Infof("[Switching] Beacon registration from %s", reg.Beacon.ID)

	// Get beacon if existing
	beacon, err := db.BeaconByID(reg.Beacon.ID)
	beaconHandlerLog.Debugf("Found %v err = %s", beacon, err)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		beaconHandlerLog.Errorf("Database query error %s", err)
		return nil
	}

	// Prepare an event, either a registration if new beacon...
	var event core.Event
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// New beacon
		beacon = &models.Beacon{
			ID: gofrsUuid.FromStringOrNil(reg.Beacon.ID),
		}
		event = core.Event{
			Type:    clientpb.EventType_BeaconRegistered,
			Beacon:  beacon,
			Session: s,
		}
	} else {
		// ... Or if we have found the beacon, update it
		event = core.Event{
			Type:    clientpb.EventType_BeaconUpdated,
			Beacon:  beacon,
			Session: s,
		}
	}

	beacon.Name = reg.Beacon.Register.Name
	beacon.Hostname = reg.Beacon.Register.Hostname
	beacon.HostUUID = gofrsUuid.FromStringOrNil(reg.Beacon.Register.HostUUID)
	beacon.Username = reg.Beacon.Register.Username
	beacon.UID = reg.Beacon.Register.Uid
	beacon.GID = reg.Beacon.Register.Gid
	beacon.OS = reg.Beacon.Register.Os
	beacon.Arch = reg.Beacon.Register.Arch
	beacon.Transport = conn.Transport
	beacon.RemoteAddress = conn.RemoteAddress
	beacon.PID = reg.Beacon.Register.Pid
	beacon.Filename = reg.Beacon.Register.Filename
	beacon.LastCheckin = conn.LastMessage
	beacon.Version = reg.Beacon.Register.Version
	beacon.ReconnectInterval = reg.Beacon.Register.ReconnectInterval
	beacon.ProxyURL = reg.Beacon.Register.ProxyURL
	beacon.PollTimeout = reg.Beacon.Register.PollTimeout
	// beacon.ConfigID = uuid.FromStringOrNil(reg.Beacon.Register.ConfigID)
	beacon.WorkingDirectory = reg.Beacon.Register.WorkingDirectory
	beacon.State = clientpb.State_Alive

	beacon.Interval = reg.Beacon.Interval
	beacon.Jitter = reg.Beacon.Jitter
	beacon.NextCheckin = reg.Beacon.NextCheckin

	if s != nil {
		beacon.SessionID = s.UUID
	}

	err = db.Session().Save(beacon).Error
	if err != nil {
		beaconHandlerLog.Errorf("Database write %s", err)
	}

	// Update the transport and connection details for the session
	beacon.TransportID = t.ID.String()
	t.Running = true
	t.SessionID = gofrsUuid.FromStringOrNil(beacon.ID.String())
	err = db.Session().Save(&t).Error
	if err != nil {
		sessionHandlerLog.Errorf("Failed to update Transport: %s", err)
	}

	// Publish the corresponding type of event for this switch
	core.EventBroker.Publish(event)

	// If we were a session, close the session and publish
	if s != nil {
		session := core.Sessions.Get(s.ID)
		if session == nil {
			return nil
		}
		core.Sessions.RemoveSwitched(session.ID)
	}

	return nil
}
