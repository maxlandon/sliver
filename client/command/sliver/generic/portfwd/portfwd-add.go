package portfwd

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
	"net"
	"time"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/tcpproxy"
	"github.com/bishopfox/sliver/client/transport"
)

// PortfwdAdd - Create a new port forwarding tunnel.
type PortfwdAdd struct {
	Options struct {
		Bind   string `long:"bind" short:"b" description:"bind port forward to interface" default:"127.0.0.1:8080" required:"yes"`
		Remote string `long:"remote" short:"r" description:"remote target host:port (e.g., 10.0.0.1:445)" required:"yes"`
	} `group:"forwarder options"`
}

// Execute - Create a new port forwarding tunnel.
func (p *PortfwdAdd) Execute(args []string) (err error) {
	session := core.ActiveTarget.Session()

	if session.GetActiveC2() == "dns" {
		log.Warnf("Current C2 is DNS, this is going to be a very slow tunnel!\n")
	}
	if session.Transport == "wg" {
		log.Warnf("Current C2 is WireGuard, we recommend using the `wg-portfwd` command!\n")
	}

	bindAddr := p.Options.Bind
	remoteAddr := p.Options.Remote
	remoteHost, remotePort, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return log.Errorf("Failed to parse remote target %s", err)
	}
	if remotePort == "3389" {
		log.Warnf("RDP is unstable over tunneled portfwds, we recommend using WireGuard portfwds\n")
	}

	tcpProxy := &tcpproxy.Proxy{}
	channelProxy := &core.ChannelProxy{
		Rpc:             transport.RPC,
		Session:         session,
		RemoteAddr:      remoteAddr,
		BindAddr:        bindAddr,
		KeepAlivePeriod: 60 * time.Second,
		DialTimeout:     30 * time.Second,
	}
	tcpProxy.AddRoute(bindAddr, channelProxy)
	core.Portfwds.Add(tcpProxy, channelProxy)

	go func() {
		err := tcpProxy.Run()
		if err != nil {
			portfwdLog.Errorf("Proxy error: %s", err)
		}
	}()

	log.Infof("Port forwarding %s -> %s:%s\n", bindAddr, remoteHost, remotePort)
	return
}
