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
	"path/filepath"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// ChangeDirectory - Change the working directory of the client console
type ChangeDirectory struct {
	Positional struct {
		Path string `description:"remote path" required:"1-1"`
	} `positional-args:"yes" required:"yes"`
}

// Execute - Handler for ChangeDirectory
func (cd *ChangeDirectory) Execute(args []string) (err error) {

	path := cd.Positional.Path
	if (path == "~" || path == "~/") && core.ActiveTarget.OS() == "linux" {
		path = filepath.Join("/home", core.ActiveTarget.Username())
	}

	pwd, err := transport.RPC.Cd(context.Background(), &sliverpb.CdReq{
		Path:    path,
		Request: core.ActiveTarget.Request(),
	})
	if err != nil {
		log.Errorf("%s", err)
	} else {
		log.Infof("%s\n", pwd.Path)
		core.ActiveTarget.Session().WorkingDirectory = pwd.Path
	}

	return
}
