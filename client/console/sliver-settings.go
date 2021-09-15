package console

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
	"encoding/json"
	"fmt"

	"google.golang.org/grpc"

	"github.com/bishopfox/sliver/client/assets"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
)

// loadSliverSettings - Once the client is connected, it receives Sliver-specific
// settings from the server, according to the user profile.
// In case of errors, it loads the builtin settings below.
func loadSliverSettings(rpc rpcpb.SliverRPCClient) (settings *assets.ClientSettings, err error) {

	req := &clientpb.GetSliverSettingsReq{}
	res, err := rpc.LoadSliverSettings(context.Background(), req, grpc.EmptyCallOption{})
	if err != nil {
		settings = loadDefaultSliverSettings()
		return settings, fmt.Errorf("RPC Error: %s", err.Error())
	}
	if res.Response.Err != "" {
		settings = loadDefaultSliverSettings()
		return settings, fmt.Errorf("%s", res.Response.Err)
	}

	// The ser has sent us a JSON struct
	settings = &assets.ClientSettings{}
	err = json.Unmarshal(res.Settings, settings)
	if err != nil {
		return settings, fmt.Errorf("Error unmarshaling config: %s", err.Error())
	}

	return
}

// loadDefaultSliverSettings - When the user has no saved settings on the server
// (or the server has not saved itself) we load this default sliver settings.
func loadDefaultSliverSettings() (settings *assets.ClientSettings) {
	return &assets.ClientSettings{
		TableStyle:        "SliverDefault",
		AutoAdult:         false,
		BeaconAutoResults: true,
	}
}
