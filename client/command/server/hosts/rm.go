package hosts

import (
	"context"
	"fmt"

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

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

// RmHost - Remove one or more hosts from the database
type RmHost struct {
	Positional struct {
		HostID []string `description:"ID of host to delete" required:"1"`
	} `positional-args:"yes" required:"true"`
}

// Execute - Remove one or more hosts from the database
func (h *RmHost) Execute(args []string) (err error) {

	allHosts, err := transport.RPC.Hosts(context.Background(), &commonpb.Empty{})
	if err != nil {
		return log.Errorf("Failed to fetch hosts: %s", err)
	}

	// Delete each host
	for _, id := range h.Positional.HostID {
		for _, host := range allHosts.Hosts {

			// Format each Host ID
			var shortID string
			if len(host.HostUUID) < 8 {
				shortID = host.HostUUID[:len(host.HostUUID)]
			} else {
				shortID = host.HostUUID[:8]
			}

			// If match, delete
			if shortID == id {
				_, err = transport.RPC.HostRm(context.Background(), host)
				if err != nil {
					err := log.Errorf("Failed to delete host %s: %s", shortID, err)
					fmt.Printf(err.Error())
					continue
				}
				log.Infof("Removed host %s from database", shortID)
			}
		}
	}
	return
}
