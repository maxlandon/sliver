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
	"fmt"

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
)

// ProfileDelete - Delete one or more profiles from the server
type ProfileDelete struct {
	Positional struct {
		Profiles []string `description:"name of profile to delete" required:"1"`
	} `positional-args:"yes" required:"true"`
}

// Execute - Command
func (pd *ProfileDelete) Execute(args []string) (err error) {
	for _, p := range pd.Positional.Profiles {
		_, err := transport.RPC.DeleteImplantProfile(context.Background(), &clientpb.DeleteReq{
			Name: p,
		})
		if err != nil {
			err := log.Errorf("Failed to delete profile: %s", err)
			fmt.Printf(err.Error())
			continue
		} else {
			log.Infof("Deleted profile %s", p)
		}
	}
	return
}
