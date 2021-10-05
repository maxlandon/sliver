package mtls

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

// Listen - Start a listener for the given context, or for a given implant
type Listen struct {
	Args struct {
		LocalAddr string `description:"host:port address to listen on"`
	} `positional-args:"yes"`

	c2.ListenerOptions
	c2.SecurityOptions
}

// Execute - Start a listener for the given context, or for a given implant
func (l *Listen) Execute(args []string) (err error) {

	// Declare profile
	profile := c2.ParseActionProfile(
		sliverpb.C2Channel_MTLS,      // A Channel using Mutual TLS
		l.Args.LocalAddr,             // Targeting the host:[port] argument of our command
		sliverpb.C2Direction_Reverse, // A listener
	)
	profile.Persistent = l.ListenerOptions.Core.Persistent

	if profile.Port == 0 {
		profile.Port = 9898
	}

	log.Infof("Starting mTLS listener (%s:%d)...", profile.Hostname, profile.Port)
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

	log.Infof("Successfully started MTLS listener")
	return
}
