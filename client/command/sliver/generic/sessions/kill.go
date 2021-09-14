package sessions

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
	"errors"
	"time"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// Kill - Kill the active session.
// Therefore this command is different from the one in Sessions struct.
type Kill struct {
	Options struct {
		Force bool `long:"force" short:"f" description:"force kill, does not clean up"`
	} `group:"kill options"`
}

// Execute - Kill the active session.
func (k *Kill) Execute(args []string) (err error) {

	session := core.ActiveTarget.Session
	err = killSession(session, transport.RPC)
	if err != nil {
		return log.Errorf("%s", err)
	}

	core.UnsetActiveSession()
	return
}

func killSession(session *clientpb.Session, rpc rpcpb.SliverRPCClient) error {
	if session == nil {
		return errors.New("Session does not exist")
	}
	_, err := rpc.KillSession(context.Background(), &sliverpb.KillSessionReq{
		Request: &commonpb.Request{
			SessionID: session.ID,
		},
		Force: true,
	})
	if err != nil {
		return err
	}

	ctrl := make(chan bool)
	go log.SpinUntil("Waiting for confirmation...", ctrl)
	time.Sleep(time.Second * 1)
	ctrl <- true
	<-ctrl
	log.Infof("Killed %s (%d)\n", session.Name, session.ID)

	return nil
}
