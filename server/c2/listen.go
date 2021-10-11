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
	"fmt"
	"net"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/c2/http"
	"github.com/bishopfox/sliver/server/comm"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/db/models"
	"github.com/sirupsen/logrus"
)

// Listen - Root function where all listeners/servers for all C2 channels are called.
// Please add a branch case for your C2 profile, where you should normally just have
// to imitate the above lines. The session is passed for providing the good network.
//
// The server automatically creates and populates a server job, but DOES NOT start it.
// Examples of useful fields in this Job:
// - Ctrl/Ticker stuff for handling/killing goroutine-based C2 handlers/monitoring stuff.
// - Cleanup() function, allows you to add additional cleanup tasks for your C2 job.
//
// The listener is nil: you can optionally assign it to a listener that you started  within
// your C2 channel implementation. The listener is then transparently handled by the job system.
func Listen(log *logrus.Entry, profile *models.Malleable, network comm.Net, job *core.Job, ln net.Listener) (err error) {

	// C2 Protocols Implementations -----------------------------------------------------------
	switch profile.Channel {

	case sliverpb.C2_TCP:

		// Use the Comm system network to automatically dispatch dial/listen
		// to the right interface (either the server's, or the active session)
		hostport := fmt.Sprintf("%s:%d", profile.Hostname, profile.Port)
		ln, err = network.Listen("tcp", hostport)
		if err != nil {
			return err
		}

	case sliverpb.C2_MTLS:

		// Start an mTLS listener on the current active session or the server interfaces.
		// The latter's cleanup is registered in InitHandlerJob()
		ln, err = ListenMutualTLS(profile, network)
		if err != nil {
			return err
		}

	case sliverpb.C2_WG:

		// Setup and start the device interface, and monitor new peers in the background
		// Specifies additional control listeners & device cleanup tasks for the job.
		tNet, err := StartWireGuardDevInterface(profile, job)
		if err != nil {
			return err
		}

		// Setup and start the WireGuard connection listener.
		// The latter's cleanup is registered in InitHandlerJob()
		// Specifies additional control listeners & device cleanup tasks (key exchange listener)
		ln, err = ListenWireGuard(profile, job, tNet)
		if err != nil {
			return err
		}

	case sliverpb.C2_DNS:

		// Start the DNS server and integrate its control/stop functions into the job
		// (No listener, Sliver connections are handled from within the DNS server implementation.)
		err = ServeDNS(profile, job)
		if err != nil {
			return err
		}

	case sliverpb.C2_HTTPS, sliverpb.C2_HTTP:

		// Instantiate a new HTTP(S) Server configured with the target C2 profile
		server, err := http.NewServerFromProfile(profile)
		if err != nil {
			return err
		}

		// Initialize the HTTP Server with job control/cleanup
		err = server.InitServer(job)
		if err != nil {
			return err
		}

		// Start the HTTP Server, handing its control to the job.
		// (No listener, Sliver connections are handled from within the HTTP server implementation.)
		// This will automatically either serve HTTP, or HTTPS with optional LetsEncrypt certs.
		err = server.Serve(job)
		if err != nil {
			return err
		}

	case sliverpb.C2_NamedPipe:

		// Listen on a pipe routed to the current active session.
		ln, err = network.Listen("pipe", profile.Hostname)
		if err != nil {
			return err
		}
	}

	// Transparent Session Handling & Job Setup ------------------------------------------------
	// If the listener is used (thus spawned/started), serve the connections
	// hitting it in the background. This will return transparently if not used/nil
	go ServeListenerConnections(log, ln)

	return
}
