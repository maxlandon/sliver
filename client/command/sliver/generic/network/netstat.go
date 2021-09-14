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
	"net"
	"strings"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// Netstat - Print session active sockets
type Netstat struct {
	Options struct {
		TCP    bool `long:"tcp" short:"t" description:"exclude TCP connections"`
		UDP    bool `long:"udp" short:"u" description:"include UDP connections"`
		IPv4   bool `long:"ip4" short:"4" description:"exclude IPv4 address sockets"`
		IPv6   bool `long:"ip6" short:"6" description:"include IPv6 address sockets"`
		Listen bool `long:"listen" short:"l" description:"include listening sockets"`
	} `group:"netstat options"`
}

// Execute - Command
func (n *Netstat) Execute(args []string) (err error) {

	listening := n.Options.Listen
	ip4 := !n.Options.IPv4 // By default WE DO NOT EXCLUDE IPv4
	ip6 := n.Options.IPv6
	tcp := !n.Options.TCP // By default WE DO NOT EXCLUDE TCP
	udp := n.Options.UDP

	netstat, err := transport.RPC.Netstat(context.Background(), &sliverpb.NetstatReq{
		TCP:       tcp,
		UDP:       udp,
		Listening: listening,
		IP4:       ip4,
		IP6:       ip6,
		Request:   core.ActiveTarget.Request(),
	})
	if err != nil {
		return log.Errorf("%s", err)
	}
	displayEntries(netstat.Entries)

	return
}

func displayEntries(entries []*sliverpb.SockTabEntry) {
	lookup := func(skaddr *sliverpb.SockTabEntry_SockAddr) string {
		const IPv4Strlen = 17
		addr := skaddr.Ip
		names, err := net.LookupAddr(addr)
		if err == nil && len(names) > 0 {
			addr = names[0]
		}
		if len(addr) > IPv4Strlen {
			addr = addr[:IPv4Strlen]
		}
		return fmt.Sprintf("%s:%d", addr, skaddr.Port)
	}

	fmt.Printf("Proto %-23s %-23s %-12s %-16s\n", "Local Addr", "Foreign Addr", "State", "PID/Program name")
	for _, e := range entries {
		p := ""
		if e.Process != nil {
			p = fmt.Sprintf("%d/%s", e.Process.Pid, e.Process.Executable)
		}
		srcAddr := lookup(e.LocalAddr)
		dstAddr := lookup(e.RemoteAddr)
		if e.Process != nil && e.Process.Pid == core.ActiveTarget.Session.PID && isSliverAddr(dstAddr) {
			fmt.Printf("%s%-5s %-23.23s %-23.23s %-12s %-16s%s\n",
				green, e.Protocol, srcAddr, dstAddr, e.SkState, p, normal)
		} else {
			fmt.Printf("%-5s %-23.23s %-23.23s %-12s %-16s\n",
				e.Protocol, srcAddr, dstAddr, e.SkState, p)
		}
	}
}

func isSliverAddr(dstAddr string) bool {
	parts := strings.Split(dstAddr, ":")
	if len(parts) != 3 {
		return false
	}
	c2Addr := strings.Split(core.ActiveTarget.Session.ActiveC2, "://")[1]
	return strings.Join(parts[:2], ":") == c2Addr
}
