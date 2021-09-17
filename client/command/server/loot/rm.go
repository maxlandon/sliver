package loot

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

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// Rm - Remove one or more pieces of loot from the server's loot store
type Rm struct {
	Positional struct {
		LootID []string `description:"IDs of loots to delete (can be more than one)" required:"1"`
	} `positional-args:"true" required:"true"`
}

// Execute - Remove one or more pieces of loot from the server's loot store
func (r *Rm) Execute(args []string) (err error) {

	allLoot, err := transport.RPC.LootAll(context.Background(), &commonpb.Empty{})
	if err != nil {
		return log.Errorf("Failed to fetch loot: %s", err)
	}

	for _, loot := range allLoot.Loot {
		for _, id := range r.Positional.LootID {
			if id == loot.LootID {
				_, err = transport.RPC.LootRm(context.Background(), loot)
				if err != nil {
					err := log.Errorf("Failed to delete loot %s: %s", loot.LootID, err)
					fmt.Printf(err.Error())
					continue
				}
				log.Infof("Removed loot %s (%s)", loot.LootID, loot.Type.String())
			}
		}
	}

	return
}
