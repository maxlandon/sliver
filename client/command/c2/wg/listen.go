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
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
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

	log.Infof("Starting Wireguard listener ...")
	wg, err := transport.RPC.StartWGListener(context.Background(), &clientpb.WGListenerReq{
		Port:       w.Options.LPort,
		NPort:      w.Options.NPort,
		KeyPort:    w.Options.KeyPort,
		Persistent: w.ListenerOptions.Core.Persistent,
	})
	if err != nil {
		return log.Error(err)
	}

	log.Infof("Successfully started job #%d", wg.JobID)
	return
}
