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

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// WireGuardPortFwdRm - Remove a port forward from the WireGuard tun interface
type WireGuardPortFwdRm struct {
	Args struct {
		ID []int32 `description:"forward rule ID" required:"1"`
	} `positional-args:"yes" required:"yes"`
}

// Execute - Remove a port forward from the WireGuard tun interface
func (w *WireGuardPortFwdRm) Execute(args []string) (err error) {

	for _, id := range w.Args.ID {

		if id == -1 {
			continue
		}

		stopReq, err := transport.RPC.WGStopPortForward(context.Background(), &sliverpb.WGPortForwardStopReq{
			ID:      id,
			Request: core.ActiveTarget.Request(),
		})

		if err != nil {
			log.Errorf("Error: %v", err)
			continue
		}

		if stopReq.Response != nil && stopReq.Response.Err != "" {
			log.Errorf("Error: %v\n", stopReq.Response.Err)
			continue
		}

		if stopReq.Forwarder != nil {
			log.Infof("Removed port forwarding rule %s -> %s\n", stopReq.Forwarder.LocalAddr, stopReq.Forwarder.RemoteAddr)
			continue
		}

	}
	return
}
