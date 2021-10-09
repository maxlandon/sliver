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
	"net/url"

	gofrsUuid "github.com/gofrs/uuid"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/comm"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/db"
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

	// Instead of creating a new session around the implant connection,
	// find the session matching the details sent in the request.
	session := core.GetSessionSwitching(register.OldTransportID)
	if session == nil {
		sessionHandlerLog.Errorf("(Transport switch) Failed to find session for transport %s", register.OldTransportID)
		return nil
	}

	// Get this new transport and implant build
	build, err := db.ImplantBuildByName(session.Name)
	transport, err := db.TransportByID(register.TransportID)
	if transport == nil || err != nil {
		sessionHandlerLog.Errorf("(Transport switch) Failed to find transport %s", register.TransportID)
		return nil
	}

	// Update the transport and connection details for the session
	session.TransportID = transport.ID.String()
	transport.Running = true
	transport.SessionID = gofrsUuid.FromStringOrNil(session.UUID)
	err = db.Session().Save(&transport).Error
	if err != nil {
		sessionHandlerLog.Errorf("Failed to update Transport: %s", err)
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
		return nil
	}

	// Update the session itself, and confirm we successfully switched the transport
	session.Connection = implantConn // If we don't update this, will deadlock on next request
	core.Sessions.UpdateSession(session)
	core.ConfirmTransportSwitched(session)

	// If this transport specifically asks not to be Comm wired, or if the
	// implant build forbids it anyway, just return, we have nothing to restart.
	if transport.Profile.CommDisabled || !build.ImplantConfig.CommEnabled {
		return nil
	}

	// Restart the Comms if required. TODO: restart active portforwarders/proxies
	err = comm.InitSession(session)
	if err != nil {
		sessionHandlerLog.Errorf("Comm init failed: %v", err)
		return nil
	}

	return nil
}
