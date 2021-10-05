package comm

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
	"errors"
	"net"
)

var (
	// A single instance of the server's network stack.
	serverNetwork = &serverNet{}
)

// serverNet - A stub implementation that just returns all functions needed from
// the standard net package. This object is hidden behind the Net interface in this package.
type serverNet struct{}

// Dial - Dial any host reachable from the server.
// Valid stream networks are "tcp", "tcp4" and "tcp6"
// Valid packet networks are "udp", "udp4" and "udp6"
func (s *serverNet) Dial(network, host string) (net.Conn, error) {
	switch network {

	case "tcp", "tcp4", "tcp6":
		raddr, err := net.ResolveTCPAddr(network, host)
		if err != nil {
			return nil, err
		}
		return net.DialTCP(network, nil, raddr)

	case "udp", "udp4", "udp6":
		raddr, err := net.ResolveUDPAddr(network, host)
		if err != nil {
			return nil, err
		}
		return net.DialUDP(network, nil, raddr)

	case "pipe":
		return nil, errors.New("named pipes are not available on the server")

	default:
		return nil, errors.New("invalid network")
	}
}

// Dial - Dial any host reachable from the server, with a context.
// Valid stream networks are "tcp", "tcp4" and "tcp6"
// Valid packet networks are "udp", "udp4" and "udp6"
func (s *serverNet) DialContext(ctx context.Context, network, host string) (net.Conn, error) {
	dialer := net.Dialer{}
	return dialer.DialContext(ctx, network, host)
}

func (s *serverNet) DialUDP(network, host string) (net.PacketConn, error) {
	raddr, err := net.ResolveUDPAddr(network, host)
	if err != nil {
		return nil, err
	}
	return net.DialUDP(network, nil, raddr)
}

// Listen - Listen on one of the host interfaces. All protocols supported
// by the std library net.Listen() function are allowed, but don't mess up.
func (s *serverNet) Listen(network, host string) (net.Listener, error) {
	return net.Listen(network, host)
}

// Listen - Listen on one of the host interfaces. All protocols supported
// by the std library net.ListenPacket() function are supported.
func (s *serverNet) ListenPacket(network, host string) (net.PacketConn, error) {
	return net.ListenPacket(network, host)
}
