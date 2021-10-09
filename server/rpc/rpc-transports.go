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
	"strings"

	"github.com/gofrs/uuid"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/c2"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/db"
	"github.com/bishopfox/sliver/server/db/models"
)

// AddTransport - Add a new transport to an implant session
func (rpc *Server) AddTransport(ctx context.Context, req *clientpb.AddTransportReq) (res *clientpb.AddTransport, err error) {

	session := core.Sessions.GetByUUID(req.Request.SessionUUID)

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

	// Check if this transport is compatible with compiled C2 stacks on the implant
	isEnabled, err := isSessionTransportEnabled(session, profile)
	if err != nil {
		return nil, err
	}
	if !isEnabled {
		return nil, fmt.Errorf("Requested protocol (%s) is not compiled into the session implant build",
			profile.Channel.String())
	}

	// Setup the Transport Profile security details
	err = c2.SetupProfileSecurity(profile, profile.Hostname)
	if err != nil {
		return nil, fmt.Errorf("Failed to initialize transport security details: %s", err)
	}

	// Make a transport object to be stored in the database
	tid, _ := uuid.NewV4()
	transport := &models.Transport{
		ID:        tid,
		SessionID: uuid.FromStringOrNil(session.UUID),
		Priority:  int(req.Priority), // By default assign the requested priority
		ProfileID: profile.ID,
		Profile:   profile,
	}

	// Update the priority based on the currently loaded transports
	transport.Priority = setTransportPriority(transport, session)

	// The ID is also passed to the profile to be sent. Not overwritten in DB
	// This will retrieve the transport (and the profile) upon registration
	var oldID = profile.ID
	profile.ID = tid

	// Make the request and the response
	sliverReq := &sliverpb.TransportAddReq{
		Priority: int32(transport.Priority), // Set the computed/adjusted priority
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

// isSessionTransportEnabled - Check that the requested C2 protocol is compiled in the targeted implant session.
func isSessionTransportEnabled(sess *core.Session, profile *models.C2Profile) (enabled bool, err error) {

	build, err := db.ImplantBuildByName(sess.Name)
	if err != nil {
		return false, fmt.Errorf("Failed to retrieve session implant build: %s", err)
	}
	config, err := db.ImplantConfigByID(build.ImplantConfig.ID.String())
	if err != nil {
		return false, fmt.Errorf("Failed to retrieve implant config for build: %s", err)
	}

	if config.RuntimeC2s == "all" {
		return true, nil
	}
	var compiledC2s = strings.Split(config.RuntimeC2s, ",")
	for _, c2 := range compiledC2s {
		if c2 == strings.ToLower(profile.Channel.String()) {
			return true, nil
		}
	}

	return false, nil
}

// setTransportPriority - Reconciles the user-requested priority with the transports currently loaded by the session.
func setTransportPriority(transport *models.Transport, session *core.Session) (order int) {

	// Get the transports for the session.
	transports, err := db.TransportsBySession(session.UUID, session.Name)
	if err != nil {
		return 0
	}

	// If the prescribed order is higher than the number of transports, just make it len+1
	if len(transports) > transport.Priority || transport.Priority == 0 {
		return len(transports)
	}

	// If the prescribed order is less, adapt all transports with new order
	for _, t := range transports {
		if t.Priority >= transport.Priority {
			t.Priority = t.Priority + 1
			err = db.Session().Save(t).Error
			if err != nil {
				rpcLog.Errorf("failed to update transport (%s) priority: %d", t.ID.String(), t.Priority)
			}
		}
	}

	return transport.Priority
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

	// Delete the transport from the database
	err = db.Session().Delete(transport).Error
	if err != nil {
		return nil, fmt.Errorf("Implant deleted the transport, but failed to delete from DB: %s", err)
	}

	return &clientpb.DeleteTransport{Response: &commonpb.Response{}}, nil
}

// SwitchTransport - Requests the active session to switch to a different C2 transport
func (rpc *Server) SwitchTransport(ctx context.Context, req *clientpb.SwitchTransportReq) (res *clientpb.SwitchTransport, err error) {

	// Get the profile matching the requested transport ID
	// Return if not found.
	transport, err := db.TransportByShortID(req.ID)
	if err != nil || transport == nil {
		// Try with long ID, just in case
		transport, err = db.TransportByID(req.ID)
		if err != nil || transport == nil {
			return nil, err
		}
	}

	// If transport is found, notify the system that this session
	// is about to switch transports, so no need to delete the session
	// altogether, just keep it so that we can update it when the new
	// transport is established.
	session := core.Sessions.GetByUUID(req.Request.SessionUUID)
	// session := core.Sessions.Get(req.Request.SessionID)
	err = core.RegisterTransportSwitch(session)
	if err != nil {
		return nil, err
	}

	// Forge the request to the implant
	sliverReq := &sliverpb.TransportSwitchReq{
		ID:      transport.ID.String(),
		Request: req.Request,
	}
	sliverRes := &sliverpb.TransportSwitch{Response: &commonpb.Response{}}

	// Send the request to the implant
	err = rpc.GenericHandler(sliverReq, sliverRes)
	if err != nil {
		// Add cancelConfirmSwitch()
		return nil, fmt.Errorf("Session returned an error: %s", err)
	}
	if !sliverRes.Success {
		// Add cancelConfirmSwitch()
		return nil, errors.New("Session returned no success, but no error")
	}

	return &clientpb.SwitchTransport{Response: &commonpb.Response{}}, nil
}

// GetTransports - Get all transports loaded and available to a session.
func (rpc *Server) GetTransports(ctx context.Context, req *clientpb.GetTransportsReq) (res *clientpb.GetTransports, err error) {

	session := core.Sessions.GetByUUID(req.Request.SessionUUID)

	transports, err := db.TransportsBySession(session.UUID, session.Name)
	if err != nil {
		return nil, fmt.Errorf("Failed to get transports: %s", err)
	}

	res = &clientpb.GetTransports{Response: &commonpb.Response{}}

	for _, transport := range transports {
		res.Transports = append(res.Transports, transport.ToProtobuf())
	}

	return res, nil
}
