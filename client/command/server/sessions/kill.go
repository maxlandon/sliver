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

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// SessionsKill - Kill one or more sessions that are not mandatorily the current one.
type SessionsKill struct {
	Positional struct {
		SessionID []uint32 `description:"session ID (multiple values accepted)" required:"1"`
	} `positional-args:"yes" required:"true"`
	Options struct {
		Force bool `long:"force" short:"f" description:"Force the session to close"`
	} `group:"kill options"`
}

// Execute - Kill one or more sessions.
func (sk *SessionsKill) Execute(args []string) (err error) {

	// Get a map of all sessions
	sessions, err := transport.RPC.GetSessions(context.Background(), &commonpb.Empty{})
	if err != nil {
		log.Errorf("%s\n", err)
		return
	}
	sessionsMap := map[uint32]*clientpb.Session{}
	for _, session := range sessions.GetSessions() {
		sessionsMap[session.ID] = session
	}
	if len(sessionsMap) == 0 {
		log.Infof("No sessions \n")
		return
	}

	// Kill each ID
	for _, id := range sk.Positional.SessionID {
		sess, ok := sessionsMap[id]
		if !ok || sess == nil {
			log.Errorf("Invalid session ID: %d\n", id)
		}

		// Kill session
		err = killSession(sess, sk.Options.Force, transport.RPC)

		// The context will be updated as soon
		// as we receive confirmation from the server
	}
	return
}

// SessionsKillAll - Kill all sessions
type SessionsKillAll struct{}

// Execute - Kill all sessions
func (ka *SessionsKillAll) Execute(args []string) (err error) {

	// Get a map of all sessions
	sessions, err := transport.RPC.GetSessions(context.Background(), &commonpb.Empty{})
	if err != nil {
		log.Errorf("%s\n", err)
		return
	}
	sessionsMap := map[uint32]*clientpb.Session{}
	for _, session := range sessions.GetSessions() {
		sessionsMap[session.ID] = session
	}
	if len(sessionsMap) == 0 {
		log.Infof("No sessions \n")
		return
	}

	// Kill all IDs
	for i := range sessionsMap {
		sess, ok := sessionsMap[i]
		if !ok || sess == nil {
			log.Errorf("Invalid session ID: %d\n", i)
		}

		// Kill session
		// The context will be updated as soon
		// as we receive confirmation from the server
		err = killSession(sess, true, transport.RPC)
	}

	return
}

func killSession(session *clientpb.Session, force bool, rpc rpcpb.SliverRPCClient) error {
	if session == nil {
		return errors.New("Session does not exist")
	}
	_, err := rpc.KillSession(context.Background(), &sliverpb.KillSessionReq{
		Request: &commonpb.Request{
			SessionID: session.ID,
		},
		Force: force,
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
