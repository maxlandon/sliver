package tcp

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

	"github.com/bishopfox/sliver/client/command/c2"
	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// Dial - Dial a remote address to connect to a listening implant
type Dial struct {
	Args struct {
		RemoteAddr string `description:"host:port address to dial"`
	} `positional-args:"yes"`

	c2.DialerOptions
}

// Execute - Dial a remote address to connect to a listening implant
func (d *Dial) Execute(args []string) (err error) {

	// Declare profile
	profile := c2.ParseActionProfile(
		sliverpb.C2Channel_TCP,    // A Channel using TCP
		d.Args.RemoteAddr,         // Targeting the host:[port] argument of our command
		sliverpb.C2Direction_Bind, // A dialer
	)

	server := profile.Hostname
	lport := uint16(profile.Port)

	log.Infof("Starting TCP dialer  ( ==>  %s:%d) ...", server, lport)
	res, err := transport.RPC.StartHandlerStage(context.Background(), &clientpb.HandlerStageReq{
		Profile: profile,
		Request: core.ActiveTarget.Request(),
	})
	if err != nil {
		return log.Error(err)
	}
	if !res.Success {
		return log.Errorf("An unknown error happened: no success")
	}

	log.Infof("Successfully executed TCP dialer")
	return
}
