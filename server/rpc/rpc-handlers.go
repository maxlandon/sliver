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
	"github.com/gofrs/uuid"
)

// StartC2Handler - A generic RPC method used to open handlers for all supported C2 channels, either on the server or on implants.
// Normally no user should have much to do here: if you want to add your C2, check server/c2/listen.go or dial.go.
func (rpc *Server) StartC2Handler(ctx context.Context, req *clientpb.HandlerStartReq) (res *clientpb.HandlerStart, err error) {

	// Any low level management stuff before anything.
	profile := models.C2ProfileFromProtobuf(req.Profile)
	session := core.Sessions.Get(req.Request.SessionID)

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
	var job *core.Job

	// Dispatch the profile to either the root Dialer functions or Listener ones.
	// The actual implementation of the C2 handlers are in there, or possibly in
	// functions still down the way.
	switch profile.Direction {

	// Dialers
	case sliverpb.C2Direction_Bind:
		err = c2.Dial(profile, net, session)
		if err != nil {
			return nil, err
		}

	// Listeners
	case sliverpb.C2Direction_Reverse:
		job, err = c2.Listen(profile, net, session)
		if err != nil {
			return nil, err
		}
	}

	// Save the job if it's marked persistent
	savePersistentJob(profile, job, session)

	return &clientpb.HandlerStart{Response: &commonpb.Response{}, Success: true}, nil
}

func savePersistentJob(profile *models.C2Profile, job *core.Job, session *core.Session) (err error) {
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
	}
	err = db.SessionJobSave(jobSave)

	return
}

// CloseC2Handler - Generic method to close a handler running either on the server or on an implant. By definition these are listeners.
func (rpc *Server) CloseC2Handler(ctx context.Context, req *clientpb.HandlerCloseReq) (res *clientpb.HandlerClose, err error) {
	return nil, status.Errorf(codes.Unimplemented, "method CloseC2Handler not implemented")
}
