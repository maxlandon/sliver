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
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// Impersonate - Impersonate a logged in user
type Impersonate struct {
	Positional struct {
		Username string `description:"user to impersonate" required:"1-1"`
	} `positional-args:"yes" required:"yes"`
}

// Execute - Impersonate a logged in user
func (i *Impersonate) Execute(args []string) (err error) {

	username := i.Positional.Username
	impResp, err := transport.RPC.Impersonate(context.Background(), &sliverpb.ImpersonateReq{
		Request:  core.ActiveTarget.Request(),
		Username: username,
	})

	if err != nil {
		return log.Errorf("Error: %v", err)
	}
	if impResp.GetResponse().GetErr() != "" {
		return log.Errorf("Error: %s", impResp.GetResponse().GetErr())
	}
	log.Infof("Successfully impersonated %s\n", username)

	return
}
