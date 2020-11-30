package transports

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
	"time"
)

var (
	defaultNetTimeout = 10 * time.Second
)

var (
	// Transports - All active transports on this implant.
	Transports = &transports{
		Active: map[uint64]*Transport{},
		mutex:  &sync.Mutex{},
	}

	// ServerComms - Only one transport is tied either to the C2 server or to a pivot implant.
	// This is a reference used for things like the routing system.
	ServerComms *Transport
)

// transports - Holds all active transports for this implant.
// This is consumed by some handlers & listeners, as well as the routing system.
type transports struct {
	Active map[uint64]*Transport // All transports with an active connection
	mutex  *sync.Mutex
}

// Add - Add a new active transport to the implant' transport map.
func (t *transports) Add(tp *Transport) (err error) {
	return
}

// Remove - A transport has terminated its connection, and we remove it.
func (t *transports) Remove(ID uint64) (err error) {
	return
}

// Get - Returns an active Transport given an ID.
func (t *transports) Get(ID uint64) (tp *Transport) {
	return
}
