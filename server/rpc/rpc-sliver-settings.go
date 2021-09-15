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
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/server/assets"
)

// LoadSliverSettings - The client requires its Sliver-specific settings (per-user)
func (rpc *Server) LoadSliverSettings(ctx context.Context, req *clientpb.GetSliverSettingsReq) (*clientpb.GetSliverSettings, error) {

	// Get an ID/operator name for this client
	name := rpc.getClientCommonName(ctx)

	// Find file data, cut it and process it. If the name is empty,
	// we are the server and we write to a dedicated file.
	var filename string
	if name == "" {
		filename = filepath.Join(assets.GetRootAppDir(), "sliver.settings")
	} else {
		path := assets.GetUserDirectory(name)
		filename = filepath.Join(path, "sliver.settings")
	}

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return &clientpb.GetSliverSettings{Response: &commonpb.Response{Err: "could not find user Sliver settings"}}, nil
	}

	if err != nil {
		return &clientpb.GetSliverSettings{Response: &commonpb.Response{Err: "failed to unmarshal user Sliver settings"}}, nil
	}

	return &clientpb.GetSliverSettings{Settings: data, Response: &commonpb.Response{}}, nil
}

// SaveUserSliverSettings - The client user wants to save its current Sliver-specific settings.
func (rpc *Server) SaveUserSliverSettings(ctx context.Context, req *clientpb.SaveSliverSettingsReq) (*clientpb.SaveSliverSettings, error) {

	// Get an ID/operator name for this client
	name := rpc.getClientCommonName(ctx)

	// Find file data, cut it and process it. If the name is empty,
	// we are the server and we write to a dedicated file.
	var filename string
	if name == "" {
		filename = filepath.Join(assets.GetRootAppDir(), "sliver.settings")
	} else {
		path := assets.GetUserDirectory(name)
		filename = filepath.Join(path, "sliver.settings")
	}

	// Write to client history file
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return &clientpb.SaveSliverSettings{Response: &commonpb.Response{Err: "Could not find and/or overwrite Sliver settings file"}}, nil
	}
	if _, err = f.Write(req.Settings); err != nil {
		return &clientpb.SaveSliverSettings{Response: &commonpb.Response{Err: "Could not write/overwrite Sliver settings file"}}, nil
	}
	f.Close()

	return &clientpb.SaveSliverSettings{Response: &commonpb.Response{}}, nil
}
