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
	"fmt"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"google.golang.org/protobuf/proto"
)

// GetEnv - Get the session's environment variables
type GetEnv struct {
	Positional struct {
		Vars []string `description:"(optional) list of environment variable names"`
	} `positional-args:"yes"`
}

// Execute - Get the session's environment variables
func (e *GetEnv) Execute(args []string) (err error) {

	_, beacon := core.ActiveTarget.Targets()

	// Get all variables if no arguments given
	if len(e.Positional.Vars) == 0 {
		e.Positional.Vars = []string{""}
	}

	for _, name := range e.Positional.Vars {

		// Request
		envInfo, err := transport.RPC.GetEnv(context.Background(), &sliverpb.EnvReq{
			Name:    name,
			Request: core.ActiveTarget.Request(),
		})
		if err != nil {
			fmt.Printf(log.Error(err).Error())
			continue
		}

		// Beacon
		if beacon != nil {
			e.executeAsync(envInfo)
			continue
		}

		// Session
		err = e.executeSync(envInfo)
		if err != nil {
			fmt.Printf(log.Error(err).Error())
			continue
		}
	}
	return
}

func (e *GetEnv) executeAsync(envInfo *sliverpb.EnvInfo) (err error) {
	if envInfo.Response != nil && envInfo.Response.Async {
		core.AddBeaconCallback(envInfo.Response.TaskID, func(task *clientpb.BeaconTask) {
			err := proto.Unmarshal(task.Response, envInfo)
			if err != nil {
				log.ErrorfAsync("Failed to decode response: %s", err)
				return
			}
			for _, envVar := range envInfo.Variables {
				log.InfofAsync(" %s=%s\n", envVar.Key, envVar.Value)
			}
		})
	}
	return nil // Always return nil from just a task assignment
}

func (e *GetEnv) executeSync(envInfo *sliverpb.EnvInfo) (err error) {
	for _, envVar := range envInfo.Variables {
		log.Infof(" %s=%s\n", envVar.Key, envVar.Value)
	}
	return
}
