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
	"fmt"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// WireGuardSocksStop - Stop a socks5 listener on the WireGuard tun interface
type WireGuardSocksStop struct {
	Args struct {
		ID []int32 `description:"socks server ID" required:"1"`
	} `positional-args:"yes" required:"yes"`
}

// Execute - Stop a socks5 listener on the WireGuard tun interface
func (w *WireGuardSocksStop) Execute(args []string) (err error) {

	for _, socksID := range w.Args.ID {

		if socksID == -1 {
			continue
		}

		stopReq, err := transport.RPC.WGStopSocks(context.Background(), &sliverpb.WGSocksStopReq{
			ID:      int32(socksID),
			Request: core.ActiveTarget.Request(),
		})

		if err != nil {
			err := log.Errorf("Error: %v", err)
			fmt.Printf(err.Error())
			continue
		}

		if stopReq.Response != nil && stopReq.Response.Err != "" {
			err := log.Errorf("Error: %v", stopReq.Response.Err)
			fmt.Printf(err.Error())
			continue
		}

		if stopReq.Server != nil {
			log.Infof("Removed socks listener rule %s \n", stopReq.Server.LocalAddr)
		}
	}

	return
}
