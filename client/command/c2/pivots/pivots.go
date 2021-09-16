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
	"errors"
	"fmt"

	"github.com/maxlandon/readline"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/client/util"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// Pivots - Pivots management command, prints them by default
type Pivots struct {
	Options struct {
		SessionID int32 `long:"id" short:"i" description:"session for which to print pivots"`
	} `group:"pivot options"`
}

// Execute - Pivots management command, prints them by default
func (p *Pivots) Execute(args []string) (err error) {
	rpc := transport.RPC
	timeout := core.GetCommandTimeout()
	sessionID := p.Options.SessionID
	if sessionID != 0 {
		session := core.GetSession(string(sessionID))
		if session == nil {
			return
		}
		printPivots(session, int64(timeout), rpc)
	} else {
		session := core.ActiveTarget.Session()
		if session != nil {
			printPivots(session, int64(timeout), rpc)
		} else {
			sessions, err := rpc.GetSessions(context.Background(), &commonpb.Empty{})
			if err != nil {
				return log.Error(err)
			}
			if len(sessions.Sessions) == 0 {
				log.Infof("No pivoted sessions")
				return nil
			}
			for _, session := range sessions.Sessions {
				printPivots(session, int64(timeout), rpc)
			}
		}
	}
	return
}

func printPivots(session *clientpb.Session, timeout int64, rpc rpcpb.SliverRPCClient) (err error) {
	pivotList, err := rpc.ListPivots(context.Background(), &sliverpb.PivotListReq{
		Request: &commonpb.Request{
			SessionID: session.ID,
			Timeout:   timeout,
			Async:     false,
		},
	})

	if err != nil {
		return err
	}

	if pivotList.Response != nil && pivotList.Response.Err != "" {
		return errors.New(pivotList.Response.Err)
	}

	if pivotList.Entries == nil || len(pivotList.Entries) == 0 {
		return fmt.Errorf("No pivots found for session %d", session.ID)
	}

	table := util.NewTable(readline.Bold(readline.Blue(fmt.Sprintf("Session %d", session.ID))))
	headers := []string{"Type", "Address"}
	headLen := []int{10, 20}
	table.SetColumns(headers, headLen)

	for _, entry := range pivotList.Entries {
		table.Append([]string{entry.Type, entry.Remote})
	}
	table.Output()

	return nil
}
