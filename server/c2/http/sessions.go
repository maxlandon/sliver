package http

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
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/cryptography"
)

// HTTPSession - Holds data related to a sliver c2 session
type HTTPSession struct {
	ID         string
	ImplanConn *core.Connection
	CipherCtx  *cryptography.CipherContext
	Started    time.Time
}

func newHTTPSession() *HTTPSession {
	return &HTTPSession{
		ID:      newHTTPSessionID(),
		Started: time.Now(),
	}
}

// newHTTPSessionID - Get a 128bit session ID
func newHTTPSessionID() string {
	buf := make([]byte, 16)
	rand.Read(buf)
	return hex.EncodeToString(buf)
}

// HTTPSessions - All currently open HTTP sessions
type HTTPSessions struct {
	active map[string]*HTTPSession
	mutex  *sync.RWMutex
}

// Add - Add an HTTP session
func (s *HTTPSessions) Add(session *HTTPSession) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.active[session.ID] = session
}

// Get - Get an HTTP session
func (s *HTTPSessions) Get(sessionID string) *HTTPSession {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.active[sessionID]
}

// Remove - Remove an HTTP session
func (s *HTTPSessions) Remove(sessionID string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.active, sessionID)
}
