package wg

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

// Listener - Create and configure a Wireguard Listener profile
type Listener struct {
	Args struct {
		LocalAddr string `description:"interface to bind WG listener to"`
	} `positional-args:"yes"`

	// Base
	c2.ProfileOptions
	c2.SecurityOptions

	// WireGuard specific
	Options struct {
		// LHost   string `long:"lhost" short:"L" description:"interface address to bind WG listener to" `
		LPort        uint32 `long:"lport" short:"L" description:"UDP listen port" default:"53"`
		NPort        uint32 `long:"nport" short:"N" description:"Virtual tun interface listen port" default:"8888"`
		KeyPort      uint32 `long:"key-port" short:"x" description:"Virtual tun interface key exchange port" default:"1337"`
		WGServerCert string `long:"wg-cert" short:"C" description:"use a precise (Wireguard) server certificate from credential store"`
		WGPrivateKey string `long:"wg-key" short:"K" description:"use a precise (WireGuard) private key from credential server"`
	} `group:"WireGuard listener options"`
}

// Execute - Create and configure a Wireguard Listener profile
func (l *Listener) Execute(args []string) (err error) {

	// Base profile
	profile := c2.NewMalleable(
		sliverpb.C2_WG,               // A Channel using Mutual TLS
		l.Args.LocalAddr,             // Targeting the host:[port] argument of our command
		sliverpb.C2Direction_Reverse, // A listener
		l.ProfileOptions,             // This will automatically parse Profile options into the protobuf
	)

	// Wireguard-specific options
	profile.Port = l.Options.LPort // Override the port value from LocalAddr, which is only an interface value
	profile.ControlPort = l.Options.NPort
	profile.KeyExchangePort = l.Options.KeyPort
	profile.Credentials.ControlServerCert = []byte(l.Options.WGServerCert)
	profile.Credentials.ControlClientKey = []byte(l.Options.WGPrivateKey)

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

	// Print profile summary
	log.Infof("Created C2 listener profile :\n")
	c2.PrintProfileSummary(res.Profile)

	return
}
