package wireguard

/*
	Sliver Implant Framework
	Copyright (C) 2021  Bishop Fox

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
	"strconv"

	"github.com/bishopfox/sliver/client/console"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/spf13/cobra"
)

// WGPortFwdRmCmd - Remove a WireGuard port forward
func WGPortFwdRmCmd(cmd *cobra.Command, args []string) {
	con := console.Client

	session := con.ActiveTarget.GetSessionInteractive()
	if session == nil {
		return
	}
	if session.Transport != "wg" {
		log.Errorf("This command is only supported for WireGuard implants")
		return
	}

	fwdID, err := strconv.Atoi(args[0])
	if err != nil {
		log.Errorf("Error converting portforward ID (%s) to int: %s", args[0], err.Error())
		return
	}

	stopReq, err := con.Rpc.WGStopPortForward(context.Background(), &sliverpb.WGPortForwardStopReq{
		ID:      int32(fwdID),
		Request: con.ActiveTarget.Request(cmd),
	})
	if err != nil {
		log.Errorf("Error: %v", err)
		return
	}

	if stopReq.Response != nil && stopReq.Response.Err != "" {
		log.Errorf("Error: %v\n", stopReq.Response.Err)
		return
	}

	if stopReq.Forwarder != nil {
		log.Infof("Removed port forwarding rule %s -> %s\n", stopReq.Forwarder.LocalAddr, stopReq.Forwarder.RemoteAddr)
	}
}
