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

// Listen - Start a WireGuard VPN listener
type Listen struct {
	Args struct {
		LocalAddr string `description:"interface to bind WG listener to"`
	} `positional-args:"yes"`

	// Base
	c2.ListenerOptions
	c2.SecurityOptions

	// WireGuard specific
	Options struct {
		// LHost   string `long:"lhost" short:"L" description:"interface address to bind WG listener to" default:""`
		LPort        uint32 `long:"lport" short:"L" description:"UDP listen port" default:"53"`
		NPort        uint32 `long:"nport" short:"N" description:"Virtual tun interface listen port" default:"8888"`
		KeyPort      uint32 `long:"key-port" short:"x" description:"Virtual tun interface key exchange port" default:"1337"`
		WGServerCert string `long:"wg-cert" short:"C" description:"use a precise (Wireguard) server certificate from credential store"`
		WGPrivateKey string `long:"wg-key" short:"K" description:"use a precise (WireGuard) private key from credential server"`
	} `group:"WireGuard listener options"`
}

// Execute - Start a WireGuard VPN listener
func (w *Listen) Execute(args []string) (err error) {

	// Declare profile
	profile := c2.ParseActionProfile(
		sliverpb.C2Channel_WG,        // A Channel using Mutual TLS
		w.Args.LocalAddr,             // Targeting the host:[port] argument of our command
		sliverpb.C2Direction_Reverse, // A listener
	)
	profile.Persistent = w.ListenerOptions.Core.Persistent

	// Wireguard-specific otions
	profile.Port = w.Options.LPort // Override the port value from LocalAddr, which is only an interface value
	profile.ControlPort = w.Options.NPort
	profile.KeyExchangePort = w.Options.KeyPort
	profile.Credentials.ControlServerCert = []byte(w.Options.WGServerCert)
	profile.Credentials.ControlClientKey = []byte(w.Options.WGPrivateKey)

	log.Infof("Starting Wireguard listener (Iface: %s, UDP Port: %d, TCP Port: %d, Key Port: %d)...",
		profile.Hostname, profile.Port, profile.ControlPort, profile.KeyExchangePort)

	res, err := transport.RPC.StartC2Handler(context.Background(), &clientpb.HandlerStartReq{
		Profile: profile,
		Request: core.ActiveTarget.Request(),
	})
	if err != nil {
		return log.Error(err)
	}
	if !res.Success {
		return log.Errorf("An unknown error happened: no success")
	}

	log.Infof("Successfully started WireGuard listener")
	return
}
