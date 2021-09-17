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

	"gopkg.in/AlecAivazis/survey.v1"

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// Rename - Rename a piece of existing loot
type Rename struct {
	Positional struct {
		LootID string `description:"IDs of loots to delete (can be more than one)" required:"1-1"`
	} `positional-args:"true" required:"true"`
}

// Execute - Rename a piece of existing loot
func (l *Rename) Execute(args []string) (err error) {

	allLoot, err := transport.RPC.LootAll(context.Background(), &commonpb.Empty{})
	if err != nil {
		return log.Errorf("Failed to fetch loot: %s", err)
	}

	var loot *clientpb.Loot
	for _, lo := range allLoot.Loot {
		if lo.LootID == l.Positional.LootID {
			loot = lo
		}
	}
	if loot == nil {
		return log.Errorf("Invalid loot ID")
	}

	oldName := loot.Name
	newName := ""
	prompt := &survey.Input{Message: "Enter new name: "}
	survey.AskOne(prompt, &newName, nil)

	loot, err = transport.RPC.LootUpdate(context.Background(), &clientpb.Loot{
		LootID: loot.LootID,
		Name:   newName,
	})
	if err != nil {
		return log.Errorf("Failed to update loot name: %s", err)
	}
	log.Infof("Renamed %s -> %s  (%s)", loot.LootID, oldName, loot.Name)
	return
}
