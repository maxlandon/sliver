package network

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
	"strconv"
	"strings"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

const (
	green  = "\033[32m"
	cyan   = "\033[36m"
	bold   = "\033[1m"
	normal = "\033[0m"
)

// Ifconfig - Show session network interfaces
type Ifconfig struct{}

// Execute - Show session network interfaces
func (i *Ifconfig) Execute(args []string) (err error) {

	ifconfig, err := transport.RPC.Ifconfig(context.Background(), &sliverpb.IfconfigReq{
		Request: core.ActiveTarget.Request(),
	})
	if err != nil {
		return log.Errorf("%s", err)
	}

	for ifaceIndex, iface := range ifconfig.NetInterfaces {
		fmt.Printf("%s%s%s (%d)\n", bold, iface.Name, normal, ifaceIndex)
		if 0 < len(iface.MAC) {
			fmt.Printf("   MAC Address: %s\n", iface.MAC)
		}
		for _, ip := range iface.IPAddresses {

			// Try to find local IPs and colorize them
			subnet := -1
			if strings.Contains(ip, "/") {
				parts := strings.Split(ip, "/")
				subnetStr := parts[len(parts)-1]
				subnet, err = strconv.Atoi(subnetStr)
				if err != nil {
					subnet = -1
				}
			}

			if 0 < subnet && subnet <= 32 && !isLoopback(ip) {
				fmt.Printf(bold+green+"    IP Address: %s%s\n", ip, normal)
			} else if 32 < subnet && !isLoopback(ip) {
				fmt.Printf(bold+cyan+"    IP Address: %s%s\n", ip, normal)
			} else {
				fmt.Printf("    IP Address: %s\n", ip)
			}
		}
	}
	return
}

func isLoopback(ip string) bool {
	if strings.HasPrefix(ip, "127") || strings.HasPrefix(ip, "::1") {
		return true
	}
	return false
}
