package generate

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

// RemoveBuild - Remove one or more implant builds from the server database
type RemoveBuild struct {
	Args struct {
		Names []string `description:"implant build name" required:"1"`
	} `positional-args:"yes" required:"yes"`
}

// Execute - Remove one or more implant builds from the server database
func (r *RemoveBuild) Execute(args []string) (err error) {

	for _, name := range r.Args.Names {
		_, err := transport.RPC.DeleteImplantBuild(context.Background(), &clientpb.DeleteReq{
			Name: name,
		})
		if err != nil {
			err := log.Errorf("Failed to delete implant %s", err)
			fmt.Printf(err.Error())
			continue
		}
		log.Infof("Deleted implant %s\n", name)

	}
	return
}
