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
	"errors"
	"fmt"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/db"
	"github.com/bishopfox/sliver/server/db/models"
	"github.com/gofrs/uuid"
)

// AddTransport - Add a new transport to an implant session
func (rpc *Server) AddTransport(ctx context.Context, req *clientpb.AddTransportReq) (res *clientpb.AddTransport, err error) {

	session := core.Sessions.Get(req.Request.SessionID)

	// Get the profile matching the requested profile ID
	// Return if not found.
	profile, err := db.C2ProfileByShortID(req.ID)
	if err != nil || profile == nil {
		// Try with long ID, just in case
		profile, err = db.C2ProfileByID(req.ID)
		if err != nil || profile == nil {
			return nil, err
		}
	}

	// Make a transport object to be stored in the database
	tid, _ := uuid.NewV4()
	transport := &models.Transport{
		ID:        tid,
		SessionID: uuid.FromStringOrNil(session.UUID),
		Priority:  int(req.Priority),
		ProfileID: profile.ID,
		Profile:   profile,
	}

	// The ID is also passed to the profile to be sent. Not overwritten in DB
	// This will retrieve the transport (and the profile) upon registration
	var oldID = profile.ID
	profile.ID = tid

	// Make the request and the response
	sliverReq := &sliverpb.TransportAddReq{
		Priority: req.Priority,
		Switch:   req.Switch,
		Profile:  profile.ToProtobuf(),
		Request:  req.Request,
	}
	sliverRes := &sliverpb.TransportAdd{Response: &commonpb.Response{}}

	// Send the profile to the implant
	err = rpc.GenericHandler(sliverReq, sliverRes)
	if err != nil {
		return nil, fmt.Errorf("Session returned an error: %s", err)
	}

	// If everything went fine, update the list of transports available to the implant
	// in the database, so that we don't have to query it each time we want them.
	// Rewrite the correct profile ID for not creating a new useless one
	profile.ID = oldID
	err = db.Session().Save(transport).Error
	if err != nil {
		return nil, fmt.Errorf("Failed to update Transport: %s", err)
	}

	return &clientpb.AddTransport{Response: &commonpb.Response{}}, nil
}

// DeleteTransport - Delete a transport loaded and available from the implant session
func (rpc *Server) DeleteTransport(ctx context.Context, req *clientpb.DeleteTransportReq) (res *clientpb.DeleteTransport, err error) {

	// Get the profile matching the requested transport ID
	// Return if not found.
	transport, err := db.TransportByID(req.ID)
	if err != nil || transport == nil {
		// Try with long ID, just in case
		transport, err = db.TransportByID(req.ID)
		if err != nil || transport == nil {
			return nil, err
		}
	}

	sliverReq := &sliverpb.TransportDeleteReq{
		ID:      transport.ID.String(),
		Request: req.Request,
	}
	sliverRes := &sliverpb.TransportDelete{Response: &commonpb.Response{}}

	// Send the request to the implant
	err = rpc.GenericHandler(sliverReq, sliverRes)
	if err != nil {
		return nil, fmt.Errorf("Session returned an error: %s", err)
	}
	if !sliverRes.Success {
		return nil, errors.New("Session returned no success, but no error")
	}

	return &clientpb.DeleteTransport{Response: &commonpb.Response{}}, nil
}

// SwitchTransport - Requests the active session to switch to a different C2 transport
func (rpc *Server) SwitchTransport(ctx context.Context, req *clientpb.SwitchTransportReq) (res *clientpb.SwitchTransport, err error) {

	// Get the profile matching the requested transport ID
	// Return if not found.
	transport, err := db.TransportByID(req.ID)
	if err != nil || transport == nil {
		// Try with long ID, just in case
		transport, err = db.TransportByID(req.ID)
		if err != nil || transport == nil {
			return nil, err
		}
	}

	sliverReq := &sliverpb.TransportSwitchReq{
		ID:      transport.ID.String(),
		Request: req.Request,
	}
	sliverRes := &sliverpb.TransportSwitch{Response: &commonpb.Response{}}

	// Send the request to the implant
	err = rpc.GenericHandler(sliverReq, sliverRes)
	if err != nil {
		return nil, fmt.Errorf("Session returned an error: %s", err)
	}
	if !sliverRes.Success {
		return nil, errors.New("Session returned no success, but no error")
	}

	return &clientpb.SwitchTransport{Response: &commonpb.Response{}}, nil
}

// GetTransports - Get all transports loaded and available to a session.
func (rpc *Server) GetTransports(ctx context.Context, req *clientpb.GetTransportsReq) (res *clientpb.GetTransports, err error) {
	session := core.Sessions.Get(req.Request.SessionID)

	transports, err := db.TransportsBySessionID(session.UUID)
	if err != nil {
		return nil, fmt.Errorf("Failed to get transports: %s", err)
	}

	res = &clientpb.GetTransports{Response: &commonpb.Response{}}

	for _, transport := range transports {
		res.Transports = append(res.Transports, transport.ToProtobuf())
	}

	return res, nil
}
