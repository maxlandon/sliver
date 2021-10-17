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
	"errors"

	"github.com/gofrs/uuid"
)

var (
	// SessionID - A unique ID for the entire lifetime of
	// this implant when using Sessions channel types.
	SessionID string

	// BeaconID - A unique ID for the entire lifetime of
	// this implant when using Beacons channel types.
	BeaconID string
)

func init() {
	// *** Session ***
	sid, err := uuid.NewV4()
	if err != nil {
		SessionID = "00000000-0000-0000-0000-000000000000"
	}
	SessionID = sid.String()

	// *** Beacon ***
	bid, err := uuid.NewV4()
	if err != nil {
		BeaconID = "00000000-0000-0000-0000-000000000000"
	}
	BeaconID = bid.String()
}

var (
	// ErrMaxAttempts - Passed by transports to the c2 controller
	ErrMaxAttempts = errors.New("reached maximum connection attempts")
)
