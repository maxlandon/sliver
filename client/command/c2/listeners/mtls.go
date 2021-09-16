package listeners

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

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
)

const (
	defaultMTLSLPort    = 8888
	defaultHTTPLPort    = 80
	defaultHTTPSLPort   = 443
	defaultDNSLPort     = 53
	defaultTCPPivotPort = 9898

	defaultReconnect = 60
	defaultMaxErrors = 1000

	defaultTimeout = 60
)

// MTLSListener - Start a mTLS listener
type MTLSListener struct {
	Options struct {
		LHost      string `long:"lhost" short:"L" description:"interface address to bind mTLS listener to" default:""`
		LPort      int    `long:"lport" short:"l" description:"listener TCP listen port" default:"8888"`
		Persistent bool   `long:"persistent" short:"p" description:"make listener persistent across server restarts"`
	} `group:"mTLS listener options"`
}

// Execute - Start a mTLS listener
func (m *MTLSListener) Execute(args []string) (err error) {
	server := m.Options.LHost
	lport := uint16(m.Options.LPort)

	if lport == 0 {
		lport = defaultMTLSLPort
	}

	log.Infof("Starting mTLS listener (%s:%d)...", m.Options.LHost, m.Options.LPort)
	mtls, err := transport.RPC.StartMTLSListener(context.Background(), &clientpb.MTLSListenerReq{
		Host:       server,
		Port:       uint32(lport),
		Persistent: m.Options.Persistent,
	})
	if err != nil {
		return log.Error(err)
	}

	log.Infof("Successfully started job #%d", mtls.JobID)
	return
}
