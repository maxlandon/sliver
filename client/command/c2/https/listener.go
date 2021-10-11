package https

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
	"github.com/bishopfox/sliver/client/command/c2/http"
	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// ListenerOptions - All listener options needed by HTTP handlers
type ListenerOptions struct {
	Options struct {
		Domain      string `long:"domain" short:"d" description:"limit responses to specific domain)"`
		LetsEncrypt bool   `long:"lets-encrypt" short:"e" description:"attempt to provision a let's encrypt certificate"`
		Website     string `long:"website" short:"w" description:"website name (see 'websites' command)"`
	} `group:"HTTP(S) listener options"`
}

// Listener - Create a new HTTPS server listener C2 Profile
type Listener struct {
	Args struct {
		LocalAddr string `description:"host:port address to bind server to"`
	} `positional-args:"yes"`

	c2.ListenerOptions
	HTTPListenerOptions ListenerOptions
	c2.ProfileOptions
	c2.SecurityOptions

	// HTTP C2 Profile configurations
	http.AdvancedOptions
}

// Execute - Create a new HTTPS server listener C2 Profile
func (l *Listener) Execute(args []string) (err error) {

	// Base profile
	profile := c2.NewMalleable(
		sliverpb.C2_HTTPS,            // A Channel using Mutual TLS
		l.Args.LocalAddr,             // Targeting the host:[port] argument of our command
		sliverpb.C2Direction_Reverse, // A listener
		l.ProfileOptions,             // This will automatically parse Profile options into the protobuf
	)

	// Add HTTP-specific options
	http.PopulateProfileHTTP(profile, l.AdvancedOptions)

	// Send this profile to the server
	req := &clientpb.CreateMalleableReq{
		Profile: profile,
		Request: core.ActiveTarget.Request(),
	}
	res, err := transport.RPC.CreateMalleable(context.Background(), req)
	if err != nil {
		if res.Response.Err != "" {
			log.PrintErrorf(err.Error())
			log.PrintErrorf(res.Response.Err)
			return nil
		}
		return log.Error(err)
	}

	log.Infof("Created C2 listener profile :\n")

	// This function knows how to format a summary of your profile, depending on its type,
	// its current options, etc. Normally it should work for most cases where you want to
	// display a C2 profile to the screen.
	c2.PrintProfileSummary(res.Profile)

	return
}
