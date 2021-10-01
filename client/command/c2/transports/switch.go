package transports

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

// Switch - Switch transports for the current session or context one
type Switch struct {
	Args struct {
		TransportID string `description:"ID of the transport you want to use" required:"1-1"`
	} `positional-args:"yes" required:"yes"`
}

// Execute - Switch transports for the current session or context one
func (s *Switch) Execute(args []string) (err error) {

	_, err = transport.RPC.SwitchTransport(context.Background(), &clientpb.SwitchTransportReq{
		ID:      s.Args.TransportID,
		Request: core.ActiveTarget.Request(),
	})
	if err != nil {
		return log.Errorf("Failed to switch transport: %s", err)
	}
	log.Infof("Switching session transport... (%s)", s.Args.TransportID)
	log.Infof("The session should update itself soon.")

	return
}
