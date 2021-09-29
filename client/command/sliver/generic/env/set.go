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
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/maxlandon/readline"
	"google.golang.org/protobuf/proto"
)

// SetEnv - Set an environment variable on the target host
type SetEnv struct {
	Positional struct {
		Key   string `description:"environment variable name" required:"1"`
		Value string `description:"environment variable value" required:"1"`
	} `positional-args:"yes" required:"yes"`
}

// Execute - Set an environment variable on the target host
func (e *SetEnv) Execute(args []string) (err error) {
	_, beacon := core.ActiveTarget.Targets()

	envInfo, err := transport.RPC.SetEnv(context.Background(), &sliverpb.SetEnvReq{
		Variable: &commonpb.EnvVar{
			Key:   e.Positional.Key,
			Value: e.Positional.Value,
		},
		Request: core.ActiveTarget.Request(),
	})
	if err != nil {
		return log.Errorf("Error: %v", err)
	}
	if envInfo.Response != nil && envInfo.Response.Err != "" {
		return log.Errorf("Error: %s", envInfo.Response.Err)
	}
	// Beacon
	if beacon != nil {
		return e.executeAsync(envInfo)
	}

	// Session
	return e.executeSync(envInfo)
}

func (e *SetEnv) executeAsync(envInfo *sliverpb.SetEnv) (err error) {

	if envInfo.Response != nil && envInfo.Response.Async {
		core.AddBeaconCallback(envInfo.Response.TaskID, func(task *clientpb.BeaconTask) {
			err := proto.Unmarshal(task.Response, envInfo)
			if err != nil {
				log.ErrorfAsync("Failed to decode response: %s", err)
				return
			}
		})
	}
	return nil // Always return nil from just a task assignment
}

func (e *SetEnv) executeSync(envInfo *sliverpb.SetEnv) (err error) {
	log.Infof("Set %s to %s", readline.Yellow(e.Positional.Key), readline.Green(e.Positional.Value))
	return
}
