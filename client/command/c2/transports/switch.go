package transports

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

	"google.golang.org/protobuf/proto"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// Switch - Switch the active transport of the current target
type Switch struct {
	Args struct {
		TransportID string `description:"ID of the transport you want to use" required:"1-1"`
	} `positional-args:"yes" required:"yes"`
}

// Execute - Switch the active transport of the current target
func (s *Switch) Execute(args []string) (err error) {
	_, beacon := core.ActiveTarget.Targets()

	// Make request
	resp, err := transport.RPC.SwitchTransport(context.Background(), &sliverpb.TransportSwitchReq{
		ID:      s.Args.TransportID,
		Request: core.ActiveTarget.Request(),
	})
	if err != nil {
		return log.Errorf("Failed to switch transport: %s", err)
	}

	// Beacon
	if beacon != nil {
		return s.executeAsync(resp)
	}

	// Session
	return s.executeSync(resp)
}

// Switch - Switch the active transport of the current target (asynchronous/beacon)
func (s *Switch) executeAsync(resp *sliverpb.TransportSwitch) (err error) {

	if resp.Response != nil && resp.Response.Async {
		core.AddBeaconCallback(resp.Response.TaskID, func(task *clientpb.BeaconTask) {
			err := proto.Unmarshal(task.Response, resp)
			if err != nil {
				log.ErrorfAsync("Failed to decode response: %s", err)
				return
			}
			if resp.Response.Err != "" {
				log.ErrorfAsync("Failed to switch transport: %s", resp.Response.Err)
				return
			}

			log.InfofAsync("Switching current transport... (%s)", s.Args.TransportID)
			log.InfofAsync("The session/beacon and connectivity status should update itself soon.")
		})
	}
	return nil // Always return nil from just a task assignment
}

// Switch - Switch the active transport of the current target (synchronous/session)
func (s *Switch) executeSync(resp *sliverpb.TransportSwitch) (err error) {
	if resp.Response.Err != "" {
		log.ErrorfAsync("Failed to switch transport: %s", resp.Response.Err)
		return
	}

	log.Infof("Switching current transport... (%s)", s.Args.TransportID)
	log.Infof("The session/beacon and connectivity status should update itself soon.")
	return
}
