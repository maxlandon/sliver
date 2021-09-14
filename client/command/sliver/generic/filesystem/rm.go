package filesystem

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

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// Rm - Remove a one or more files/directories from the implant target host.
type Rm struct {
	Positional struct {
		Path []string `description:"session directory/file" required:"1"`
	} `positional-args:"yes" required:"yes"`
	Options struct {
		Recursive bool `long:"recursive " short:"r" description:"recursively remove directory contents"`
		Force     bool `long:"force" short:"f" description:"ignore nonexistent files, never prompt"`
	} `group:"rm options"`
}

// Execute - Command
func (rm *Rm) Execute(args []string) (err error) {

	for _, other := range rm.Positional.Path {
		res, err := transport.RPC.Rm(context.Background(), &sliverpb.RmReq{
			Path:      other,
			Recursive: rm.Options.Recursive,
			Force:     rm.Options.Force,
			Request:   core.ActiveTarget.Request(),
		})
		if err != nil {
			err := log.Errorf("%s", err)
			fmt.Printf(err.Error())
		} else {
			log.Infof("Removed %s\n", res.Path)
		}
	}
	return
}
