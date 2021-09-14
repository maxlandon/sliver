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
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
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

	envInfo, err := transport.RPC.SetEnv(context.Background(), &sliverpb.SetEnvReq{
		Variable: &commonpb.EnvVar{
			Key:   e.Positional.Key,
			Value: e.Positional.Value,
		},
		Request: core.ActiveTarget.Request(),
	})
	if err != nil {
		log.Errorf("Error: %v", err)
		return
	}
	if envInfo.Response != nil && envInfo.Response.Err != "" {
		log.Errorf("Error: %s", envInfo.Response.Err)
		return
	}
	log.Infof("set %s to %s\n", e.Positional.Key, e.Positional.Value)

	return
}
