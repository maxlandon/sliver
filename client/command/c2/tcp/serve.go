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

// Serve - Serve an implant stage with an TCP server
type Serve struct {
	Args struct {
		LocalAddr string `description:"interface:[port] to bind the TCP server to" required:"yes"`
	} `positional-args:"yes"`
	c2.StagerOptions
	c2.ListenerOptions
}

// Execute - Serve an implant stage with a TCP listener
func (s *Serve) Execute(args []string) (err error) {

	//Base profile
	profile := c2.ParseActionProfile(
		sliverpb.C2Channel_TCP,
		s.Args.LocalAddr,
		sliverpb.C2Direction_Reverse,
	)
	profile.Persistent = s.ListenerOptions.Core.Persistent

	// Prepare request
	req := &clientpb.HandlerStagerReq{
		Profile: profile,
		Request: core.ActiveTarget.Request(),
	}

	// Parse stager options and set the request accordingly
	err = c2.ParseStagerOptions(req, s.StagerOptions)
	if err != nil {
		return log.Errorf("Failed to set up stage: %s", err)
	}

	log.Infof("Starting TCP stage listener - %s:%d (%s) ...", profile.Hostname, profile.Port, profile.Domains[0])
	res, err := transport.RPC.StartHandlerStager(context.Background(), req)
	if err != nil {
		return log.Error(err)
	}
	if !res.Success {
		return log.Errorf("An unknown error happened: no success")
	}

	log.Infof("Successfully started TCP stage listener")
	return
}
