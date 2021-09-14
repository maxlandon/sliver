package execute

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

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
)

// Migrate - Migrate into a remote process
type Migrate struct {
	Positional struct {
		PID uint32 `description:"PID of process to migrate into" required:"1-1"`
	} `positional-args:"yes" required:"yes"`
}

// Execute - Migrate into a remote process
func (m *Migrate) Execute(args []string) (err error) {
	pid := m.Positional.PID
	if err != nil {
		log.Errorf("Error: %v", err)
	}
	config := core.GetActiveSessionConfig()
	ctrl := make(chan bool)
	msg := fmt.Sprintf("Migrating into %d ...", pid)
	go log.SpinUntil(msg, ctrl)
	migrate, err := transport.RPC.Migrate(context.Background(), &clientpb.MigrateReq{
		Pid:     pid,
		Config:  config,
		Request: core.ActiveTarget.Request(),
	})

	if err != nil {
		log.Errorf("Error: %v", err)
		return
	}
	ctrl <- true
	<-ctrl
	if !migrate.Success {
		log.Errorf("%s\n", migrate.GetResponse().GetErr())
		return
	}
	log.Infof("Successfully migrated to %d\n", pid)
	return
}
