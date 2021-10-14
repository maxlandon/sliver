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

	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/c2"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/db"
	"github.com/bishopfox/sliver/server/db/models"
)

// AddTransport - Add a new transport to an implant session
func (rpc *Server) AddTransport(ctx context.Context, req *sliverpb.TransportAddReq) (res *sliverpb.TransportAdd, err error) {

	session, beacon := core.GetActiveTarget(req.Request)
	var targetID string
	if session != nil {
		targetID = session.UUID
	} else {
		targetID = beacon.ID.String()
	}

	// Get the profile matching the requested profile ID
	profile, err := db.MalleableByShortID(req.ID)
	if err != nil || profile == nil {
		// Try with long ID, just in case
		profile, err = db.MalleableByID(req.ID)
		if err != nil || profile == nil {
			return nil, err
		}
	}

	// Check if this transport is compatible with compiled C2 stacks on the implant
	err = isSessionTransportEnabled(session, beacon, profile)
	if err != nil {
		return nil, err
	}

	// Verify that all security details (certs, keys, logins, etc)
	// are correct for the C2 profile target, type, direction.
	err = c2.SetupMalleableSecurity(profile, profile.Hostname)
	if err != nil {
		return nil, fmt.Errorf("Failed to initialize transport security details: %s", err)
	}

	// Make a transport object to be stored in the database
	tid, _ := uuid.NewV4()
	transport := &models.Transport{
		ID:        tid,
		SessionID: uuid.FromStringOrNil(targetID),
		Priority:  req.Priority, // By default assign the requested priority
		ProfileID: profile.ID,
		Profile:   profile,
	}
	transport.Priority = setTransportPriority(transport, session, beacon)

	// The ID is also passed to the profile to be sent. Not overwritten in DB
	// This will retrieve the transport (and the profile) upon registration
	var oldID = profile.ID
	profile.ID = tid

	// Make the request and the response
	sliverReq := &sliverpb.TransportAddReq{
		Priority: int32(transport.Priority),
		Switch:   req.Switch,
		Profile:  profile.ToProtobuf(),
		Request:  req.Request,
	}
	sliverRes := &sliverpb.TransportAdd{Response: &commonpb.Response{}}

	// If we have requested to switch to it now, register the switch
	if req.Switch {
		err = core.RegisterTransportSwitch(session, beacon)
		if err != nil {
			return nil, err
		}
	}

	// Send the profile to the implant
	err = rpc.GenericHandler(sliverReq, sliverRes)
	if err != nil {
		return nil, fmt.Errorf("Session returned an error: %s", err)
	}

	// If everything went fine, update the list of transports available to the implant
	// in the database, so that we don't have to query it each time we want them.
	// Rewrite the correct profile ID for not creating a new useless one
	profile.ID = oldID
	_, err = core.CreateOrUpdateTransport(transport, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to update Transport: %s", err)
	}

	return sliverRes, nil
}

// isSessionTransportEnabled - Check that the requested C2 protocol is compiled in the targeted implant session.
func isSessionTransportEnabled(sess *core.Session, beacon *models.Beacon, profile *models.Malleable) error {

	var buildName string
	if beacon != nil {
		buildName = beacon.Name
	}
	if sess != nil {
		buildName = sess.Name
	}
	build, err := db.ImplantBuildByName(buildName)
	if err != nil {
		return fmt.Errorf("Failed to retrieve session implant build: %s", err)
	}
	config, err := db.ImplantConfigByID(build.ImplantConfig.ID.String())
	if err != nil {
		return fmt.Errorf("Failed to retrieve implant config for build: %s", err)
	}

	if config.RuntimeC2s == "all" {
		return nil
	}
	var compiledC2s = strings.Split(config.RuntimeC2s, ",")
	for _, c2 := range compiledC2s {
		if c2 == strings.ToLower(profile.Channel.String()) {
			return nil
		}
	}

	return fmt.Errorf("Protocol (%s) not compiled in the implant build", profile.Channel.String())
}

// setTransportPriority - Reconciles the user-requested priority with the transports currently loaded by the session.
func setTransportPriority(transport *models.Transport, session *core.Session, beacon *models.Beacon) (order int32) {

	// Get the transports for the target
	transports, err := core.TransportsByTarget(session, beacon)
	if err != nil {
		return 0
	}

	// If the prescribed order is higher than the number of transports, just make it len+1
	if int32(len(transports)) > transport.Priority || transport.Priority == 0 {
		return int32(len(transports))
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
func (rpc *Server) DeleteTransport(ctx context.Context, req *sliverpb.TransportDeleteReq) (res *sliverpb.TransportDelete, err error) {

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

	return sliverRes, nil
}

// SwitchTransport - Requests the active session to switch to a different C2 transport
func (rpc *Server) SwitchTransport(ctx context.Context, req *sliverpb.TransportSwitchReq) (res *sliverpb.TransportSwitch, err error) {

	session, beacon := core.GetActiveTarget(req.Request)

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
	err = core.RegisterTransportSwitch(session, beacon)
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

	return sliverRes, nil
}

// GetTransports - Get all transports loaded and available to a session.
func (rpc *Server) GetTransports(ctx context.Context, req *sliverpb.TransportsReq) (res *sliverpb.Transports, err error) {
	session, beacon := core.GetActiveTarget(req.Request)
	if session == nil && beacon == nil {
		return nil, errors.New("Could not find active target")
	}

	var transports []*models.Transport
	transports, err = core.TransportsByTarget(session, beacon)
	if err != nil {
		return nil, err
	}

	res = &sliverpb.Transports{Response: &commonpb.Response{}}

	for _, transport := range transports {
		res.Transports = append(res.Transports, transport.ToProtobuf())
	}

	return res, nil
}
