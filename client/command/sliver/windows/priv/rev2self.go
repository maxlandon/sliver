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

// Rev2Self - Revert to self: lose stolen Windows token
type Rev2Self struct{}

// Execute - Revert to self: lose stolen Windows token
func (rs *Rev2Self) Execute(args []string) (err error) {

	_, err = transport.RPC.RevToSelf(context.Background(), &sliverpb.RevToSelfReq{
		Request: core.ActiveTarget.Request(),
	})

	if err != nil {
		return log.Errorf("Error: %v", err)
	}
	log.Infof("Back to self...\n")
	return nil
}
