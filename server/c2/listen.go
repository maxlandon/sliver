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
	"crypto/tls"
	"fmt"
	"net"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/comm"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/cryptography"
	"github.com/bishopfox/sliver/server/db/models"
)

// Listen - Root function where all listeners/servers for all C2 channels are called.
// Please add a branch case for your C2 profile, where you should normally just have
// to imitate the above lines. The session is passed for providing the good network.
func Listen(profile *models.C2Profile, network comm.Net, session *core.Session) (job *core.Job, err error) {

	// ln - When you spawn some sort of listener for your C2, use this listener
	// so that the Sliver server can correctly orchestrate jobs and that you can
	// kill it whenever you want, transparently.
	var ln net.Listener

	switch profile.Channel {
	case sliverpb.C2Channel_MTLS:

		// Fetch a TLS configuration from the values in the profile
		tlsConfig := cryptography.TLSConfigFromProfile(profile)

		// Use the Comm system network to automatically dispatch dial/listen
		// to the right interface (either the server's, or the active session)
		hostport := fmt.Sprintf("%s:%d", profile.Hostname, profile.Port)
		clear, err := network.Listen("tcp", hostport)
		if err != nil {
			return nil, err
		}

		// Upgrade to TLS, with certs loaded for mutual authentication
		ln = tls.NewListener(clear, tlsConfig)

		// Pass the listener to a generic function that will accept,
		// handle and wrap connections into a Session connection.
		// Use this function for any handler using a net.Listener.
		go HandleSessionConnections(ln)

	case sliverpb.C2Channel_HTTPS:
	case sliverpb.C2Channel_DNS:
	case sliverpb.C2Channel_WG:
	}

	// Create and return a job based on this profile. This is part of the
	// function returned objects because in some instances the job won't
	// be registered as alive again, like for persistent session jobs.
	// NOTE: You normally don't have to touch to this or the content of this function.
	return NewHandlerJob(profile, ln, session), nil
}
