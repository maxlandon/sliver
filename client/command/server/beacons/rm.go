package beacons

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
	"context"
	"fmt"

	"github.com/bishopfox/sliver/client/command/c2"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// BeaconsRm - Remove one or more beacons from the server
type BeaconsRm struct {
	Positional struct {
		BeaconID []string `description:"beacon ID (multiple values accepted)" required:"1"`
	} `positional-args:"yes" required:"true"`
}

// Execute - Remove one or more beacons from the server
func (r *BeaconsRm) Execute(args []string) (err error) {

	// Get a map of all beacons
	beacons, err := transport.RPC.GetBeacons(context.Background(), &commonpb.Empty{})
	if err != nil {
		return log.Error(err)
	}
	beaconsMap := map[string]*clientpb.Beacon{}
	for _, beacon := range beacons.GetBeacons() {
		beaconsMap[c2.GetShortID(beacon.ID)] = beacon
	}
	if len(beaconsMap) == 0 {
		log.Infof("No beacons")
		return
	}

	// Remove each ID
	for _, id := range r.Positional.BeaconID {
		beacon, ok := beaconsMap[id]
		if !ok || beacon == nil {
			err := log.Errorf("Invalid beacon ID: %s", id)
			fmt.Println(err.Error())
			continue
		}

		// Remove
		_, err = transport.RPC.RmBeacon(context.Background(), beacon)
		if err != nil {
			err := log.Errorf("Failed to remove beacon: %s", err)
			fmt.Println(err.Error())
			continue
		}
		log.Infof("Beacon removed (%s)", beacon.ID)
	}
	return
}
