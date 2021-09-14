package settings

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
	"encoding/json"

	"google.golang.org/grpc"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
)

// SaveConfig - Save the current console configuration on the Sliver server, so that
// all clients spawned by this user can have the same settings.
type SaveConfig struct{}

// Execute - Save the current console configuration.
func (c *SaveConfig) Execute(args []string) (err error) {

	currentConf := core.Console.GetConfig()
	confBytes, err := json.Marshal(currentConf)
	if err != nil {
		log.Errorf("Error marshaling config: %s\n", err.Error())
	}

	req := &clientpb.SaveConsoleConfigReq{
		Config: confBytes,
	}
	res, err := transport.RPC.SaveUserConsoleConfig(context.Background(), req, grpc.EmptyCallOption{})
	if err != nil {
		log.RPCErrorf("%v\n", err)
		return
	}

	if res.Response.Err != "" {
		log.Errorf("Error saving config: %s\n", res.Response.Err)
	} else {
		log.Infof("Saved console config\n")
	}
	return
}
