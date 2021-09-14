package proc

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

// Terminate - Terminate one or more processes runing on the host.
type Terminate struct {
	Positional struct {
		PID []int32 `description:"process ID to dump memory from" required:"1"`
	} `positional-args:"yes" required:"yes"`
	Options struct {
		Force bool `long:"force" short:"f" description:"disregard safety and kill the PID"`
	} `group:"kill options"`
}

// Execute - Terminate one or more processes runing on the host.
func (t *Terminate) Execute(args []string) (err error) {

	// For each process ID send a request to kill.
	for _, pid := range t.Positional.PID {
		terminated, err := transport.RPC.Terminate(context.Background(), &sliverpb.TerminateReq{
			Pid:     int32(pid),
			Force:   t.Options.Force,
			Request: core.ActiveTarget.Request(),
		})
		if err != nil {
			log.Errorf("%s\n", err)
		} else {
			log.Infof("Process %d has been terminated\n", terminated.Pid)
		}
	}
	return
}
