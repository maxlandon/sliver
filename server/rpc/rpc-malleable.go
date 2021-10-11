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

	"gorm.io/gorm/clause"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/server/db"
	"github.com/bishopfox/sliver/server/db/models"
)

// CreateMalleable - Create a new C2 profile
func (rpc *Server) CreateMalleable(ctx context.Context, req *clientpb.CreateMalleableReq) (*clientpb.CreateMalleable, error) {

	// Parse Protobuf profile into a DB suited one
	profile := models.C2ProfileFromProtobuf(req.Profile)

	// If we can find a C2 profile that has:
	// The same context session
	// The same full target path
	// The same direction
	// The same beaconing options
	// The same security options

	// Create the C2 profile in the database
	dbSession := db.Session()
	err := dbSession.Create(profile).Error
	if err != nil {
		return nil, err
	}

	// Fetch a fresh version of the object, with pretty good certainty no collisions
	profile, err = db.C2ProfileByHostPortNameSession(req.Profile.Hostname,
		req.Profile.Port,
		req.Profile.Name,
		req.Profile.ContextSessionID)
	if err != nil {
		return nil, err
	}

	res := &clientpb.CreateMalleable{
		Profile:  profile.ToProtobuf(),
		Response: &commonpb.Response{},
	}

	return res, nil
}

// DeleteMalleable - Delete a Malleable C2 profile
func (rpc *Server) DeleteMalleable(ctx context.Context, req *clientpb.DeleteMalleableReq) (res *clientpb.DeleteMalleable, err error) {

	profile, err := db.C2ProfileByID(req.Profile.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to find profile: %s", err)
	}
	err = db.Session().Delete(profile).Error
	if err != nil {
		return nil, fmt.Errorf("failed to delete profile: %s", err)
	}

	return &clientpb.DeleteMalleable{Response: &commonpb.Response{}}, nil
}

// UpdateMalleable - Update a C2 profile with new values
func (rpc *Server) UpdateMalleable(ctx context.Context, req *clientpb.UpdateMalleableReq) (res *clientpb.UpdateMalleable, err error) {

	profile := models.C2ProfileFromProtobuf(req.Profile)
	if err != nil {
		return nil, fmt.Errorf("failed to find profile: %s", err)
	}
	result := db.Session().Clauses(clause.OnConflict{
		UpdateAll: true,
	}).Create(&profile)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to update profile: %s", result.Error)
	}

	return &clientpb.UpdateMalleable{Response: &commonpb.Response{}, Updated: profile.ToProtobuf()}, nil
}

// GetMalleables - Get either all of some C2 profiles based on filters/context provided in the request
func (rpc *Server) GetMalleables(context.Context, *clientpb.GetMalleablesReq) (*clientpb.GetMalleables, error) {
	res := &clientpb.GetMalleables{}

	profiles := []*models.Malleable{}
	err := db.Session().Find(&profiles).Error
	if err != nil {
		return nil, err
	}

	for _, prof := range profiles {
		// There are two kinds or profiles saved in the database for correct
		// functioning purposes but that we never want to have in results for profiles:
		// 1 - Profiles that are marked persistent, are only meant to be used by listeners
		// 2 - Profiles marked anonymous, which are only compiled into implants.
		if !prof.Anonymous && !prof.Persistent {
			res.Profiles = append(res.Profiles, prof.ToProtobuf())
		}
	}

	return res, nil
}
