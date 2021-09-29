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
	pb "github.com/bishopfox/sliver/protobuf/sliverpb"
)

// Beacon - The most basic Beacon-style C2 channel interface. All beacons Must implement this interface.
type Beacon interface {
	// Action
	Start() error                // Start handling a beacon-style C2 channel with its appropriate parameters
	Recv() (*pb.Envelope, error) // Receive a a task from the server
	Send(*pb.Envelope) error     // Send the results or part of a task output back to server
	Close() error                // Close an C2 beacon channel instance. Might be many calls

	// Parameters
	Interval() int64
	Jitter() int64
	Duration() int64
}

type beacon struct {
}

// Action
// Start - Start handling a beacon-style C2 channel with its appropriate parameters
func (b *beacon) Start() error {
	panic("not implemented") // TODO: Implement
}

// Recv - Receive a a task from the server
func (b *beacon) Recv() (*pb.Envelope, error) {
	panic("not implemented") // TODO: Implement
}

// Send - Send the results or part of a task output back to server
func (b *beacon) Send(_ *pb.Envelope) error {
	panic("not implemented") // TODO: Implement
}

// Close an C2 beacon channel instance. Might be many calls
func (b *beacon) Close() error {
	panic("not implemented") // TODO: Implement
}

// Parameters
func (b *beacon) Interval() int64 {
	panic("not implemented") // TODO: Implement
}

func (b *beacon) Jitter() int64 {
	panic("not implemented") // TODO: Implement
}

func (b *beacon) Duration() int64 {
	panic("not implemented") // TODO: Implement
}
