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

	"github.com/sirupsen/logrus"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/c2/http"
	"github.com/bishopfox/sliver/server/comm"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/db/models"
)

// Serve - Listen and serve a stage payload over a specific protocol or C2 stack.
// The listener parameter is a placeholder, which you can use if you intend to use (at least one).
// This listener is already registered for cleanup when the stager handler job will be killed
func Serve(log *logrus.Entry, profile *models.Malleable, network comm.Net, job *core.Job, ln net.Listener) (err error) {

	switch profile.Channel {

	case sliverpb.C2_TCP:

		// Use the Comm system network to automatically dispatch dial/listen
		// to the right interface (either the server's, or the active session)
		hostport := fmt.Sprintf("%s:%d", profile.Hostname, profile.Port)
		ln, err = network.Listen("tcp", hostport)
		if err != nil {
			return err
		}

	case sliverpb.C2_HTTP, sliverpb.C2_HTTPS:

		// Instantiate a new HTTP(S) Server configured with the target C2 profile
		server, err := http.NewServerFromProfile(profile)
		if err != nil {
			return err
		}

		// Add the payload to be served through HTTP
		server.SliverStage = job.StageBytes

		// Initialize the HTTP Server with job control/cleanup
		err = server.InitServer(job)
		if err != nil {
			return err
		}

		// Start the HTTP Server, handing its control to the job.
		// (No listener, Sliver connections are handled from within the HTTP server implementation.)
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

	// Transparent Stager Handling & Job Setup ------------------------------------------------
	// If the listener is used (thus spawned/started), serve the stage request connections
	// hitting it in the background. This will return transparently if not used/nil
	go ServeStagerConnections(log, ln, job.StageBytes)

	return
}
