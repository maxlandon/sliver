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
	"errors"
	"sync"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/db"
	"github.com/bishopfox/sliver/server/db/models"
	"github.com/bishopfox/sliver/server/log"

	consts "github.com/bishopfox/sliver/client/constants"
)

var (
	sessionsLog = log.NamedLogger("core", "sessions")

	// Sessions - Manages implant connections
	Sessions = &sessions{
		sessions: map[uint32]*Session{},
		mutex:    &sync.RWMutex{},
	}
	rollingSessionID = uint32(0)

	// ErrUnknownMessageType - Returned if the implant did not understand the message for
	//                         example when the command is not supported on the platform
	ErrUnknownMessageType = errors.New("Unknown message type")

	// ErrImplantTimeout - The implant did not respond prior to timeout deadline
	ErrImplantTimeout = errors.New("Implant timeout")
)

// Session - Represents a connection to an implant
type Session struct {
	// Base
	ID               uint32
	BeaconID         string // Associated runtime beacon, if any
	UUID             string
	Name             string
	Hostname         string
	Username         string
	HostUUID         string
	UID              string
	GID              string
	Os               string
	Version          string
	Arch             string
	PID              int32
	Filename         string
	Burned           bool
	Extensions       []string
	ConfigID         string
	WorkingDirectory string
	State            clientpb.State

	// Transports
	Connection *ImplantConnection
	Transport  *models.Transport
}

func (s *Session) LastCheckin() time.Time {
	return s.Connection.LastMessage
}

func (s *Session) CurrentState() clientpb.State {
	// If we are marked switching, there is a good reason:
	if s.State == clientpb.State_Switching {
		return s.State
	}
	// As well, for the disconnect, but should only be used for beacons
	if s.State == clientpb.State_Disconnect {
		return s.State
	}
	// Sleeping might also be set by a command
	if s.State == clientpb.State_Sleep {
		return s.State
	}

	transport := s.Transport.Profile

	sessionsLog.Debugf("Last checkin was %v", s.Connection.LastMessage)
	padding := time.Duration(10 * time.Second) // Arbitrary margin of error
	timePassed := time.Now().Sub(s.LastCheckin())
	reconnect := time.Duration(transport.Interval)
	pollTimeout := time.Duration(transport.PollTimeout)
	if timePassed < reconnect+padding && timePassed < pollTimeout+padding {
		sessionsLog.Debugf("Last message within reconnect interval / poll timeout with padding")
		return clientpb.State_Alive
	}
	if s.Connection.Transport == consts.MtlsStr {
		if time.Now().Sub(s.Connection.LastMessage) < 2*time.Minute+padding {
			sessionsLog.Debugf("Last message within ping interval with padding")
			return clientpb.State_Alive
		}
	}
	return clientpb.State_Dead
}

// ToProtobuf - Get the protobuf version of the object
func (s *Session) ToProtobuf() *clientpb.Session {
	return &clientpb.Session{
		ID:               uint32(s.ID),
		UUID:             s.UUID,
		BeaconID:         s.BeaconID,
		Name:             s.Name,
		Hostname:         s.Hostname,
		Username:         s.Username,
		HostUUID:         s.HostUUID,
		UID:              s.UID,
		GID:              s.GID,
		OS:               s.Os,
		Version:          s.Version,
		Arch:             s.Arch,
		PID:              int32(s.PID),
		Filename:         s.Filename,
		LastCheckin:      s.LastCheckin().Unix(),
		State:            s.CurrentState(),
		Burned:           s.Burned,
		WorkingDirectory: s.WorkingDirectory,
		// ConfigID:          s.ConfigID,
		Transport: s.Transport.ToProtobuf(),
	}
}

// Request - Sends a protobuf request to the active sliver and returns the response
func (s *Session) Request(msgType uint32, timeout time.Duration, data []byte) ([]byte, error) {
	resp := make(chan *sliverpb.Envelope)
	reqID := EnvelopeID()
	s.Connection.RespMutex.Lock()
	s.Connection.Resp[reqID] = resp
	s.Connection.RespMutex.Unlock()
	defer func() {
		s.Connection.RespMutex.Lock()
		defer s.Connection.RespMutex.Unlock()
		// close(resp)
		delete(s.Connection.Resp, reqID)
	}()
	s.Connection.Send <- &sliverpb.Envelope{
		ID:   reqID,
		Type: msgType,
		Data: data,
	}

	var respEnvelope *sliverpb.Envelope
	select {
	case respEnvelope = <-resp:
	case <-time.After(timeout):
		return nil, ErrImplantTimeout
	}
	if respEnvelope.UnknownMessageType {
		return nil, ErrUnknownMessageType
	}
	return respEnvelope.Data, nil
}

// UpdateWorkingDirectory - Updated when either cd is invoked successfully,
// or if comparison does not match. TODO: Push event to all consoles, if they're using it.
func (s *Session) UpdateWorkingDirectory(path string) {
	s.WorkingDirectory = path
}

// sessions - Manages the slivers, provides atomic access
type sessions struct {
	mutex    *sync.RWMutex
	sessions map[uint32]*Session
}

// All - Return a list of all sessions
func (s *sessions) All() []*Session {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	all := []*Session{}
	for _, session := range s.sessions {
		all = append(all, session)
	}
	return all
}

// Get - Get a session by ID
func (s *sessions) Get(sessionID uint32) *Session {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	if s, found := s.sessions[sessionID]; found {
		return s
	}
	return nil
}

// Get - Get a session by UUID
func (s *sessions) GetByUUID(sessionUUID string) *Session {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	for _, sess := range s.sessions {
		if sess.UUID == sessionUUID {
			return sess
		}
	}
	return nil
}

// GetActiveTarget - Get either active beacon or active session for the current request
func GetActiveTarget(req *commonpb.Request) (sess *Session, beacon *models.Beacon) {
	sess = Sessions.GetByUUID(req.SessionUUID)
	beacons, _ := db.ListBeacons()
	for _, b := range beacons {
		if b.ID.String() == req.BeaconID {
			beacon = b
		}
	}
	return
}

// GetSessionContext - Get the active session for a request
func GetSessionContext(req *commonpb.Request) *Session {
	return Sessions.GetByUUID(req.SessionUUID)
}

// Add - Add a sliver to the hive (atomically)
func (s *sessions) Add(session *Session) *Session {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.sessions[session.ID] = session
	EventBroker.Publish(Event{
		Type:    clientpb.EventType_SessionOpened,
		Session: session,
	})
	return session
}

// Remove - Remove a sliver from the hive (atomically), or just update
// it if the session was just updating its transport mechanism.
func (s *sessions) Remove(sessionID uint32) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	session, found := s.sessions[sessionID]
	if !found || session == nil {
		return
	}

	// If the session is currenly switching, don't return delete:
	// we will clean it later
	if session.State == clientpb.State_Switching {
		sessionsLog.Infof("Did not delete session marked switching")
		return
	}

	// Delete the transports set at runtime if this was a kill call
	err := CleanupSessionTransports(session)
	if err != nil {
		sessionsLog.Errorf("Failed to cleanup session transports: %s", err)
	}

	// And notify the clients
	delete(s.sessions, sessionID)
	EventBroker.Publish(Event{
		Type:    clientpb.EventType_SessionClosed,
		Session: session,
	})
}

// RemoveSwitched - Remove a session and publish the event only if the session
// was marked switching: the switch is now complete, we must clean up.
func (s *sessions) RemoveSwitched(sessionID uint32) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	session, found := s.sessions[sessionID]
	if !found || session == nil || session.State != clientpb.State_Switching {
		return
	}

	delete(s.sessions, sessionID)

	// Simply notify the clients, do not clean runtime transports
	EventBroker.Publish(Event{
		Type:    clientpb.EventType_SessionClosed,
		Session: session,
	})
}

// NewSession - Create a session on top on a logical implant connection.
func NewSession(implantConn *ImplantConnection) *Session {
	implantConn.UpdateLastMessage()
	return &Session{
		ID:         nextSessionID(),
		Connection: implantConn,
	}
}

// SessionFromImplantConnection - Find the logical implant connection used by a session.
func SessionFromImplantConnection(conn *ImplantConnection) *Session {
	Sessions.mutex.RLock()
	defer Sessions.mutex.RUnlock()
	for _, session := range Sessions.sessions {
		if session.Connection.ID == conn.ID {
			return session
		}
	}
	return nil
}

// nextSessionID - Returns an incremental nonce as an id
func nextSessionID() uint32 {
	newID := rollingSessionID + 1
	rollingSessionID++
	return newID
}

func (s *sessions) UpdateSession(session *Session) *Session {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// If the transport is currently being switched
	s.sessions[session.ID] = session

	EventBroker.Publish(Event{
		Type:    clientpb.EventType_SessionUpdated,
		Session: session,
	})
	return session
}
