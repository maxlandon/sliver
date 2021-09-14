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

// WireGuardSocks - Manage WireGuard-based Socks proxies. Prints them by default
type WireGuardSocks struct {
}

// Execute - Lists WireGuard-based Socks proxies.
func (w *WireGuardSocks) Execute(args []string) (err error) {

	socksList, err := transport.RPC.WGListSocksServers(context.Background(), &sliverpb.WGSocksServersReq{
		Request: core.ActiveTarget.Request(),
	})

	if err != nil {
		log.Errorf("Error: %v", err)
		return
	}

	if socksList.Response != nil && socksList.Response.Err != "" {
		log.Errorf("Error: %s\n", socksList.Response.Err)
		return
	}

	if socksList.Servers == nil || len(socksList.Servers) == 0 {
		log.Infof("No WireGuard Socks proxies\n")
		return
	}

	table := util.NewTable("WireGuard Socks Proxies \n")

	headers := []string{"ID", "Local Address"}
	headLen := []int{5, 20}
	table.SetColumns(headers, headLen)

	for _, proxy := range socksList.Servers {
		table.Append([]string{strconv.Itoa(int(proxy.ID)), proxy.LocalAddr})
	}
	table.Output()

	return
}
