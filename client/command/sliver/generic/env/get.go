package env

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
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// GetEnv - Get the session's environment variables
type GetEnv struct {
	Positional struct {
		Vars []string `description:"environment variable name"`
	} `positional-args:"yes"`
}

// Execute - Get the session's environment variables
func (e *GetEnv) Execute(args []string) (err error) {

	// Get all variables if no arguments given
	if len(e.Positional.Vars) == 0 {
		e.Positional.Vars = []string{""}
	}

	for _, name := range e.Positional.Vars {
		envInfo, err := transport.RPC.GetEnv(context.Background(), &sliverpb.EnvReq{
			Name:    name,
			Request: core.ActiveTarget.Request(),
		})

		if err != nil {
			log.Errorf("Error: %v", err)
			continue
		}

		for _, envVar := range envInfo.Variables {
			log.Infof(" %s=%s\n", envVar.Key, envVar.Value)
		}
	}
	return
}
