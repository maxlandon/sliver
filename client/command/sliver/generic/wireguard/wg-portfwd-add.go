package wireguard

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
	"net"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// WireGuardPortFwdAdd - Add a port forward from the WireGuard tun interface to a host on the target network.
type WireGuardPortFwdAdd struct {
	Options struct {
		Bind   int32  `long:"bind" short:"b" description:"port to listen on the WireGuard tun interface" default:"1080"`
		Remote string `long:"remote" short:"r" description:"remote target host:port (e.g., 10.0.0.1:445)" required:"yes"`
	} `group:"forwarder options"`
}

// Execute - Add a port forward from the WireGuard tun interface to a host on the target network.
func (w *WireGuardPortFwdAdd) Execute(args []string) (err error) {

	remoteHost, remotePort, err := net.SplitHostPort(w.Options.Remote)
	if err != nil {
		return log.Errorf("Failed to parse remote target %s", err)
	}

	pfwdAdd, err := transport.RPC.WGStartPortForward(context.Background(), &sliverpb.WGPortForwardStartReq{
		LocalPort:     w.Options.Bind,
		RemoteAddress: w.Options.Remote,
		Request:       core.ActiveTarget.Request(),
	})

	if err != nil {
		return log.Errorf("Error: %v", err)
	}

	if pfwdAdd.Response != nil && pfwdAdd.Response.Err != "" {
		return log.Errorf("Error: %s", pfwdAdd.Response.Err)
	}
	log.Infof("Port forwarding %s -> %s:%s\n", pfwdAdd.Forwarder.LocalAddr, remoteHost, remotePort)

	return
}
