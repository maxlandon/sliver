package loot

import (
	"context"
	"os"

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
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

// Fetch - Fetch a piece of loot from the server's loot store
type Fetch struct {
	Positional struct {
		LocalPath string   `description:"local file (for one loot arg) or directory (for many) where to save" required:"1-1"`
		LootID    []string `description:"IDs of one or more loots to fetch" required:"1"`
	} `positional-args:"true" required:"true"`
	Options struct {
		Output bool `long:"output" short:"o" description:"if true, display each loot fetched to the console"`
	} `group:"loot fetch options"`
}

// Execute - Fetch a piece of existing loot from the server's loot store
func (l *Fetch) Execute(args []string) (err error) {
	saveTo := l.Positional.LocalPath

	// If path is not dir and more than one arguments, return
	fi, err := os.Stat(saveTo)
	if err != nil && !os.IsNotExist(err) {
		return log.Errorf("Invalid local path: %s", err)
	}
	if err == nil && !fi.IsDir() && len(l.Positional.LootID) > 1 {
		return log.CommandErrorf("The path to save is not a directory, and you want to fetch multiple files.")
	}

	// Get loots
	allLoot, err := transport.RPC.LootAll(context.Background(), &commonpb.Empty{})
	if err != nil {
		return log.Errorf("Failed to fetch loot: %s", err)
	}

	// Save each loot
	for _, loot := range allLoot.Loot {
		for _, id := range l.Positional.LootID {
			if id == loot.LootID {

				// Handle loot based on its type
				if l.Options.Output {
					switch loot.Type {
					case clientpb.LootType_LOOT_FILE:
						PrintLootFile(loot)
					case clientpb.LootType_LOOT_CREDENTIAL:
						PrintLootCredential(loot)
					}
				}

				// And write to disk
				savedTo, err := saveLootToDisk(saveTo, loot)
				if err != nil {
					log.Errorf("Failed to save loot %s: %s", loot.Name, err)
					continue
				}
				log.Infof("Saved loot %s to %s\n", loot.Name, savedTo)
			}
		}
	}

	return
}
