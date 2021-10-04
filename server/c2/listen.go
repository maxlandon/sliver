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

	// WireGuard C2

	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/comm"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/db/models"
)

// Listen - Root function where all listeners/servers for all C2 channels are called.
// Please add a branch case for your C2 profile, where you should normally just have
// to imitate the above lines. The session is passed for providing the good network.
func Listen(profile *models.C2Profile, network comm.Net, session *core.Session) (job *core.Job, err error) {

	// Automatic C2 handler & Job Setup -------------------------------------------------------

	// The server automatically creates and populates a server job, but DOES NOT start it.
	// Examples of useful fields in this Job:
	// - Ctrl/Ticker stuff for handling/killing goroutine-based C2 handlers/monitoring stuff.
	// - Cleanup() function, allows you to add additional cleanup tasks for your C2 job.
	//
	// The listener is nil: you can optionally assign it to a listener that you started  within
	// your C2 channel implementation. The listener is then transparently handled by the job system.
	job, ln := NewHandlerJob(profile, session)

	// C2 Protocols Implementations -----------------------------------------------------------
	switch profile.Channel {

	case sliverpb.C2Channel_MTLS:

		// Start an mTLS listener on the current active session or the server interfaces.
		// The latter's cleanup is registered in InitHandlerJob()
		ln, err = ListenMutualTLS(profile, network)
		if err != nil {
			return nil, err
		}

	case sliverpb.C2Channel_WG:

		// Setup and start the device interface, and monitor new peers in the background
		// Specifies additional control listeners & device cleanup tasks for the job.
		tNet, err := StartWireGuardDevInterface(profile, job)
		if err != nil {
			return nil, err
		}

		// Setup and start the WireGuard connection listener.
		// The latter's cleanup is registered in InitHandlerJob()
		// Specifies additional control listeners & device cleanup tasks (key exchange listener)
		ln, err = ListenWireGuard(profile, job, tNet)
		if err != nil {
			return nil, err
		}

	case sliverpb.C2Channel_DNS:

	case sliverpb.C2Channel_HTTPS:
	}

	// Transparent Session Service & Job Setup ------------------------------------------------

	// If the listener is used (thus spawned/started), serve the connections
	// hitting it in the background. This will return transparently if not used/nil
	go ServeListenerConnections(ln)

	// If we are here, it means the C2 stack has successfully started
	// (within what can be guaranteed excluding goroutine-based stuff).
	// Assign an order value to this job and register it to the server job & event system.
	InitHandlerJob(job, ln)

	return job, nil
}
