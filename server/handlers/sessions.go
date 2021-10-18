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
	"fmt"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

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

func registerSessionHandler(conn *core.Connection, data []byte) *sliverpb.Envelope {
	if conn == nil {
		return nil
	}
	register := &sliverpb.Register{}
	err := proto.Unmarshal(data, register)
	if err != nil {
		sessionHandlerLog.Errorf("Error decoding session registration message: %s", err)
		return nil
	}

	// Core ------------------------------------------------------------
	session := core.NewSession(conn)

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
	session.Version = register.Version
	session.ConfigID = register.ConfigID
	session.WorkingDirectory = register.WorkingDirectory
	session.State = clientpb.State_Alive.String()

	// Transports ------------------------------------------------------

	// Update all transports, including the running one, with their statistics
	err = core.UpdateTargetTransports(register.ActiveTransportID, session.UUID, conn, register.TransportStats)
	if err != nil {
		sessionHandlerLog.Errorf("Error when updating session transports: %s", err)
	}

	// And query back the updated, current transport
	transport, err := db.TransportByID(register.ActiveTransportID)
	if transport == nil {
		sessionHandlerLog.Errorf("Could not find transport with ID %s", register.ActiveTransportID)
	}
	session.Transport = transport

	// Registration ----------------------------------------------------

	core.Sessions.Add(session)
	conn.Cleanup = func() {
		core.Sessions.Remove(session.ID)
	}
	go auditLogSession(session, register)

	// Comm System & Jobs ----------------------------------------------

	// Finally, set up the Comm subsystem if the transport requires it.
	err = SetSessionCommSubsystem(session.Transport, session)
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
func SetSessionCommSubsystem(transport *models.Transport, session *core.Session) (err error) {

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
func tunnelDataHandler(implantConn *core.Connection, data []byte) *sliverpb.Envelope {
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

func tunnelCloseHandler(implantConn *core.Connection, data []byte) *sliverpb.Envelope {
	session := core.SessionFromImplantConnection(implantConn)
	tunnelHandlerMutex.Lock()
	defer tunnelHandlerMutex.Unlock()

	tunnelData := &sliverpb.TunnelData{}
	proto.Unmarshal(data, tunnelData)
	if !tunnelData.Closed {
		return nil
	}
	tunnel := core.Tunnels.Get(tunnelData.TunnelID)
	// The tunnel can be a core one, used for interactive system shells or various executions
	if tunnel != nil {
		if session.ID == tunnel.SessionID {
			sessionHandlerLog.Infof("Closing tunnel %d", tunnel.ID)
			core.Tunnels.Close(tunnel.ID)
		} else {
			sessionHandlerLog.Warnf("Warning: Session %d attempted to send data on tunnel it did not own", session.ID)
		}
	}

	commTunnel := comm.Tunnels.Tunnel(tunnelData.TunnelID)
	if commTunnel != nil {
		if session.ID == commTunnel.Sess.ID {
			sessionHandlerLog.Infof("Closing tunnel %d", commTunnel.ID)
			comm.Tunnels.RemoveTunnel(commTunnel.ID)
		} else {
			sessionHandlerLog.Warnf("Warning: Session %d attempted to send data on tunnel it did not own", session.ID)
		}
	} else {
		sessionHandlerLog.Warnf("Close sent on nil tunnel %d (not found either in Core or Comm tunnels)", tunnelData.TunnelID)
	}
	return nil
}

func pingHandler(implantConn *core.Connection, data []byte) *sliverpb.Envelope {
	session := core.SessionFromImplantConnection(implantConn)
	sessionHandlerLog.Debugf("ping from session %d", session.ID)
	return nil
}

// commTunnelDataHandler - Handle Comm tunnel data coming from the server.
func commTunnelDataHandler(conn *core.Connection, data []byte) *sliverpb.Envelope {
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

// switchSession - Create a session if the current target was a beacon, or update the session if it was already one.
func switchSession(s *core.Session, bc *models.Beacon, r *sliverpb.Register) error {
	var sessionExists bool
	if s.UUID == "" {
		sessionExists = false
	} else {
		sessionExists = true
	}

	// Core ---------------------------------------------------------
	hostUUID, err := uuid.Parse(r.HostUUID)
	if err != nil {
		hostUUID = uuid.New() // Generate Random UUID
	}
	s.UUID = r.UUID
	s.Name = r.Name
	s.Hostname = r.Hostname
	s.HostUUID = hostUUID.String()
	s.Username = r.Username
	s.UID = r.Uid
	s.GID = r.Gid
	s.Os = r.Os
	s.Arch = r.Arch
	s.PID = r.Pid
	s.Filename = r.Filename
	s.Version = r.Version
	s.ConfigID = r.ConfigID
	s.WorkingDirectory = r.WorkingDirectory
	s.State = clientpb.State_Alive.String()
	if bc != nil {
		s.BeaconID = bc.ID.String() // Switching from a beacon
	}

	// Registration -------------------------------------------------

	// If we were a beacon: add session and update beacon
	if !sessionExists {
		if bc != nil {
			core.Sessions.AddFromBeacon(s, bc)
		} else {
			core.Sessions.Add(s)
		}
		go auditLogSession(s, r)
	} else {
		core.Sessions.UpdateSession(s)
	}

	// We were a beacon: mark it inactive, so it doesn't
	// show up in some completions, cannot be used, etc
	if bc != nil {
		bc.State = clientpb.State_Disconnect.String()

		// And don't save either the transport or the tasks:
		///both have been handled already.
		err = db.UpdateBeaconSwitched(bc)
		if err != nil {
			beaconHandlerLog.Errorf("Database write %s", err)
		}

		// Publish
		core.EventBroker.Publish(core.Event{
			Type:   clientpb.EventType_BeaconUpdated,
			Beacon: bc,
		})
	}

	// Comm System & Jobs ----------------------------------------------

	err = SetSessionCommSubsystem(s.Transport, s)
	if err != nil {
		sessionHandlerLog.Errorf("Comm init failed: %v", err)
		return nil
	}

	return nil
}
