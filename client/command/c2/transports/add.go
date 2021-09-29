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

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
)

// Add - Add a C2 profile to a session as an available transport
type Add struct {
	Args struct {
		ProfileID string `description:"ID of the C2 Profile to load" required:"1-1"`
	} `positional-args:"yes" required:"yes"`

	Options struct {
		Switch   bool `long:"switch" short:"s" description:"immediately switch the session transport to this one"`
		Priority int  `long:"priority" short:"p" description:"order in which to insert the transport (defaults to last+1)"`
	} `group:"add options"`
}

// Execute - Add a C2 profile to a session as an available transport
func (a *Add) Execute(args []string) (err error) {

	_, err = transport.RPC.AddTransport(context.Background(), &clientpb.AddTransportReq{
		ID:       a.Args.ProfileID,
		Switch:   a.Options.Switch,
		Priority: int32(a.Options.Priority),
		Request:  core.ActiveTarget.Request(),
	})
	if err != nil {
		return log.Errorf("Failed to add transport: %s", err)
	}
	log.Infof("Added transport %s to session", a.Args.ProfileID)

	return
}
