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

	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

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

func (c *ImplantConnection) UpdateLastMessage() {
	c.LastMessage = time.Now()
}

func NewImplantConnection(transport string, remoteAddress string) *ImplantConnection {
	return &ImplantConnection{
		ID:            generateImplantConnectionID(),
		Send:          make(chan *sliverpb.Envelope),
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
func RegisterTransportSwitch(sess *Session) (err error) {

	// If the session is already marked switching (which should
	// not happen), notify the caller it's not possible to do it now.
	if _, found := Sessions.switching[sess.ID]; found {
		return fmt.Errorf("Session %d (%s) is already currently switching its transport", sess.ID, sess.UUID)
	}

	// Else add it to the map.
	Sessions.mutex.RLock()
	defer Sessions.mutex.RUnlock()
	Sessions.switching[sess.ID] = sess

	return
}

// ConfirmTransportSwitched - Once the transport has been successfully changed, notify
// the server that we're done with the process and that we can unmark the session.
func ConfirmTransportSwitched(sess *Session) {
	Sessions.mutex.Lock()
	defer Sessions.mutex.Unlock()
	session := Sessions.switching[sess.ID]
	if session != nil {
		delete(Sessions.switching, sess.ID)
	}
}

// GetSessionSwitching - When sending the registration message following the transport
// switch, the session has provided the ID of its old transport, which should be unique
// among all sessions. Find it and return it for update.
func GetSessionSwitching(oldTransportID string) (sess *Session) {
	for _, s := range Sessions.switching {
		if s.TransportID == oldTransportID {
			return s
		}
	}
	return
}
