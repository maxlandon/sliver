package tcp

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

	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// Dial - Dial TCP implant transport.
func Dial(uri *url.URL, p *sliverpb.C2Profile) (conn net.Conn, err error) {
	// {{if .Config.Debug}}
	log.Printf("Connecting -> %s", uri.Host)
	// {{end}}
	lport, err := strconv.Atoi(uri.Port())
	if err != nil {
		lport = 8888
	}

	conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", uri.Hostname(), uint16(lport)))
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Unable to connect: %v", err)
		// {{end}}
		return nil, err
	}
	if conn == nil {
		// {{if .Config.Debug}}
		log.Printf("No error and no TCP connection")
		// {{end}}
		return nil, errors.New("failed to connect, but no errors")
	}

	return conn, nil
}
