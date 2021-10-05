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
	"errors"
	"fmt"
	"net"
	"net/url"
)

// ListenPipe - Returns a Pipe listener started on a valid network address anywhere in either
// the server interfaces, or any implant's interface if the latter is served by an active route.
func ListenPipe(name string) (ln net.Listener, err error) {

	addr, err := url.Parse(fmt.Sprintf("pipe://%s", name))
	if err != nil {
		return nil, fmt.Errorf("comm listener: could not parse URL: pipe://%s", name)
	}

	// Check routes and interfaces
	route, err := ResolveURL(addr)
	if err != nil {
		return nil, err
	}

	// No route, use server interfaces, make a Pipe dest addrss and dial.
	if route == nil {
		// ip := net.ParseIP(addr.Hostname())
		// port, _ := strconv.Atoi(addr.Port())
		// tcpAddr := &net.TCPAddr{IP: ip, Port: port}
		//
		// return net.Listen("tcp", tcpAddr)
		return nil, errors.New("Named pipes cannot be used on the server")
	}

	// This produces a valid PipeAddr, which also remotely starts the handler on the implant.
	ln, err = newListenerTCP(addr, route.comm)
	if err != nil {
		return nil, fmt.Errorf("comm listener: %s", err.Error())
	}

	return ln, nil
}

// ListenPipe - Returns a listener started on a valid network address anywhere in either the server interfaces,
// or any implant's interface if the latter is served by an active route. Valid networks are "tcp".
func (c *Comm) ListenPipe(name string) (ln net.Listener, err error) {
	addr, err := url.Parse(fmt.Sprintf("pipe://%s", name))
	if err != nil {
		return nil, fmt.Errorf("comm listener: could not parse URL: pipe://%s", name)
	}

	// This produces a valid PipeAddr, which also remotely starts the handler on the implant.
	ln, err = newListenerTCP(addr, c)
	if err != nil {
		return nil, fmt.Errorf("comm listener: %s", err.Error())
	}

	return ln, nil
}
