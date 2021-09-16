package pivots

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
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// NamedPipePivot - Start a Named pipe pivot listener
type NamedPipePivot struct {
	Options struct {
		Name string `long:"name" short:"n" description:"name of the pipe" required:"yes"`
	} `group:"named pipe options"`
}

// Execute - Start a named pipe pivot listener
func (tp *NamedPipePivot) Execute(args []string) (err error) {

	pipeName := tp.Options.Name
	_, err = transport.RPC.NamedPipes(context.Background(), &sliverpb.NamedPipesReq{
		PipeName: pipeName,
		Request:  core.ActiveTarget.Request(),
	})

	if err != nil {
		return log.Errorf("Failed to start named pipe pivot listener: %s", err)
	}

	log.Infof("Listening on %s", "\\\\.\\pipe\\"+pipeName)
	return
}
