package c2

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
	"sync"
)

var (
	// Transports - All active transports on the server.
	Transports = &transports{
		Active: map[uint32]*Transport{},
		mutex:  &sync.Mutex{},
	}
	transportID = uint32(0)
)

// transports - Holds all active transports for the server.
// This is consumed by some handlers & listeners, as well as the routing system.
type transports struct {
	Active map[uint32]*Transport // All transports with an active Session connection
	mutex  *sync.Mutex
}

// Add - Add a new active transport to the server.
func (t *transports) Add(tp *Transport) (err error) {
	t.mutex.Lock()
	t.Active[tp.ID] = tp
	t.mutex.Unlock()
	return
}

// Remove - A transport has terminated its connection, and we remove it.
func (t *transports) Remove(ID uint32) (err error) {
	t.mutex.Lock()
	delete(t.Active, ID)
	t.mutex.Unlock()
	return
}

// Get - Returns an active Transport given an ID.
func (t *transports) Get(ID uint32) (tp *Transport) {
	tp, _ = t.Active[ID]
	return
}

// GetBySession - Used when we have the ID of the implant that is at the other end
// of one of our server's transports. Useful to add entry route handlers.
func (t *transports) GetBySession(ID uint32) *Transport {
	for _, tp := range t.Active {
		if tp.Session.ID == ID {
			return tp
		}
	}
	return nil
}

// nextTransportID - Returns an incremental nonce as an id
func nextTransportID() uint32 {
	newID := transportID + 1
	transportID++
	return newID
}
