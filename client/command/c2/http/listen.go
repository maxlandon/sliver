package http

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

// Listen - Start an HTTP listener on the server
type Listen struct {
	Args struct {
		LocalAddr string `description:"interface:[port] to bind the HTTP server to"`
	} `positional-args:"yes"`

	c2.ListenerOptions

	HTTPOptions struct {
		Domain string `long:"domain" short:"d" description:"limit responses to specific domain)"`
	} `group:"HTTP(S) listener options"`

	AdvancedOptions
}

// Execute - Start an HTTPS listener on the server
func (l *Listen) Execute(args []string) (err error) {

	// Declare profile
	profile := c2.NewHandlerC2(
		sliverpb.C2_HTTP,             // A Channel using Mutual TLS
		l.Args.LocalAddr,             // Targeting the host:[port] argument of our command
		sliverpb.C2Direction_Reverse, // A listener
	)
	profile.Persistent = l.ListenerOptions.Core.Persistent

	// HTTP-specific options
	profile.Domains = []string{l.HTTPOptions.Domain} // Restrict responses to this domain
	PopulateProfileHTTP(profile, l.AdvancedOptions)

	log.Infof("Starting HTTP %s:%d listener (%s)...", profile.Hostname, profile.Port, profile.Domains[0])
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

	log.Infof("Successfully started HTTP listener")
	return
}
