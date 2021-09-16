package profiles

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

	"github.com/bishopfox/sliver/client/command/server/generate"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
)

// NewProfile - Configure and save a new implant profile.
type NewProfile struct {
	generate.StageOptions // This commands works the same as generate, and needs full options.
}

// Execute - Configure and save a new implant profile.
func (p *NewProfile) Execute(args []string) (err error) {

	name := p.CoreOptions.Profile
	if name == "" {
		return log.Errorf("Invalid profile name")
	}

	config, err := generate.ParseCompileFlags(p.StageOptions)
	if err != nil {
		return log.Error(err)
	}

	profile := &clientpb.ImplantProfile{
		Name:   name,
		Config: config,
	}
	resp, err := transport.RPC.SaveImplantProfile(context.Background(), profile)

	if err != nil {
		return log.Error(err)
	}

	log.Infof("Saved new profile %s\n", resp.Name)
	return
}
