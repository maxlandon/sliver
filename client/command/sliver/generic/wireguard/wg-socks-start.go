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

// WireGuardSocksStart - Start a socks5 listener on the WireGuard tun interface
type WireGuardSocksStart struct {
	Options struct {
		Bind int32 `long:"bind" short:"b" description:"port to listen on the WireGuard tun interface" default:"3090"`
	}
}

// Execute - Start a socks5 listener on the WireGuard tun interface
func (w *WireGuardSocksStart) Execute(args []string) (err error) {

	socks, err := transport.RPC.WGStartSocks(context.Background(), &sliverpb.WGSocksStartReq{
		Port:    w.Options.Bind,
		Request: core.ActiveTarget.Request(),
	})

	if err != nil {
		return log.Errorf("Error: %v", err)
	}

	if socks.Response != nil && socks.Response.Err != "" {
		return log.Errorf("Error: %v", err)
	}

	if socks.Server != nil {
		log.Infof("Started SOCKS server on %s\n", socks.Server.LocalAddr)
	}
	return
}
