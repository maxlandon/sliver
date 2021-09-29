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
	"io"
	"net"

	"github.com/gofrs/uuid"

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

		hostport := fmt.Sprintf("%s:%d", profile.Hostname, profile.Port)
		clear, err := network.Listen("tcp", hostport)
		if err != nil {
			return nil, err
		}

		// Upgrade to TLS, with certs loaded for mutual authentication
		ln = tls.NewListener(clear, tlsConfig)
		go acceptSliverConnections(ln)

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

// NewHandlerJob - An easy function allowing a C2 developper to directly add its handler
// to the list of jobs. He can pass either a net.Listener or a net.Conn, which will be
// closed when the job is killed. This also manages jobs running on sessions, even persistent ones.
func NewHandlerJob(profile *models.C2Profile, conn io.Closer, session *core.Session) (job *core.Job) {

	// Base elements applying for all jobs, no matter where they run
	var host string
	if profile.Port > 0 {
		host = fmt.Sprintf("%s:%d%s", profile.Hostname, profile.Port, profile.Path)
	} else {
		host = fmt.Sprintf("%s%s", profile.Hostname, profile.Path)
	}

	id, _ := uuid.NewV4()
	description := fmt.Sprintf(profile.Channel.String(), profile.Channel.Type, host, id)

	// Base job with these info.
	job = &core.Job{
		ID:          id,
		Name:        profile.Channel.String(),
		Description: comm.SetHandlerCommString(host, session),
		JobCtrl:     make(chan bool),
		Profile:     profile.ToProtobuf(),
	}

	// If the job is running on a session, we assign the specifics
	if session != nil {
		job.SessionID = session.UUID
		job.SessionName = session.Name
		job.SessionUsername = session.Username
	}

	// The order is computed based on where the job is running.
	job.Order = core.Jobs.NextSessionJobCount(session)

	// Set the control channel for users to kill the job,
	// and the various cleaning functions for listeners and conns.
	go func(description string) {
		<-job.JobCtrl
		if conn != nil {
			conn.Close()
		}
		core.Jobs.Remove(job)
	}(description)

	// Finally add the job so everyone notices it.
	core.Jobs.Add(job)

	return
}
