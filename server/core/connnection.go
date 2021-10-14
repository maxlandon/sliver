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
	"sync"
	"time"

	"github.com/gofrs/uuid"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

func init() {
	// Always cleanup all transports that are not compiled in a build
	// and do not have a valid beacon ID (the beacon might be rolling still)
	CleanupOrphanedTransports()
}

// Connection - Implementation of a logical connection system around
// a C2 channel (whether net.Conn based or not). This object is neither a
// pure net.Conn implementation neither an idiomatic RPC system, but halfway both.
type Connection struct {
	ID        string
	Send      chan *sliverpb.Envelope
	RespMutex *sync.RWMutex
	Resp      map[int64]chan *sliverpb.Envelope
	Cleanup   func()

	// Runtime Information
	LastMessage   time.Time
	Transport     string
	LocalAddress  string
	RemoteAddress string
}

// UpdateLastMessage - Update the time at which the session sent its last message.
func (c *Connection) UpdateLastMessage() {
	c.LastMessage = time.Now()
}

// NewImplantConnection - A physical connection needs to be wrapped into a Session connection.
func NewImplantConnection(transport string, lAddr, rAddr string) *Connection {
	return &Connection{
		ID:            generateImplantConnectionID(),
		Send:          make(chan *sliverpb.Envelope, 100),
		RespMutex:     &sync.RWMutex{},
		Resp:          map[int64]chan *sliverpb.Envelope{},
		Transport:     transport,
		LocalAddress:  lAddr,
		RemoteAddress: rAddr,
		Cleanup:       func() {},
	}
}

func generateImplantConnectionID() string {
	id, _ := uuid.NewV4()
	return id.String()
}
