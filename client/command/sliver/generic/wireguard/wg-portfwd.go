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
	"strconv"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/client/util"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// WireGuardPortFwd - Manage WireGuard-based port forwarders. Lists them by default.
type WireGuardPortFwd struct {
}

// Execute - List WireGuard-based port forwarders.
func (w *WireGuardPortFwd) Execute(args []string) (err error) {

	fwdList, err := transport.RPC.WGListForwarders(context.Background(), &sliverpb.WGTCPForwardersReq{
		Request: core.ActiveTarget.Request(),
	})

	if err != nil {
		log.Errorf("Error: %v", err)
		return
	}

	if fwdList.Response != nil && fwdList.Response.Err != "" {
		log.Errorf("Error: %s\n", fwdList.Response.Err)
		return
	}

	if fwdList.Forwarders == nil || len(fwdList.Forwarders) == 0 {
		log.Infof("No port forwards\n")
		return
	}

	table := util.NewTable("")
	headers := []string{"ID", "Local Address", "Remote Address"}
	headLen := []int{5, 20, 20}
	table.SetColumns(headers, headLen)

	for _, fwd := range fwdList.Forwarders {
		table.Append([]string{strconv.Itoa(int(fwd.ID)), fwd.LocalAddr, fwd.RemoteAddr})
	}
	table.Output()

	return
}
