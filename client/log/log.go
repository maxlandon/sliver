package log

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
	"time"

	"github.com/evilsocket/islazy/tui"
	"github.com/maxlandon/readline"
	"github.com/sirupsen/logrus"

	consts "github.com/bishopfox/sliver/client/constants"
	cctx "github.com/bishopfox/sliver/client/context"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/client/util"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
)

const (
	eventBufferDefault = 200
)

var (
	// Rerefrences to console components, used by all loggers.
	shell        *readline.Instance
	promptRender func() string
)

// Init - The client starts monitoring all event logs coming from itself, or the server
func Init(sh *readline.Instance, render func() string, rpc rpcpb.SliverRPCClient) error {
	if sh == nil || render == nil {
		return errors.New("missing shell instance or prompt rendering function")
	}
	if transport.RPC == nil {
		return errors.New("No connected RPC client")
	}
	// Keep references for loggers
	shell = sh
	promptRender = render

	// Here all client text loggers will work out of the box.
	// Now we start monitoring server events in a separate loop
	go handleServerLogs(rpc)

	return nil
}

// handleServerEvents - Print events coming from the server
func handleServerLogs(rpc rpcpb.SliverRPCClient) {

	// Call the server events stream.
	events, err := rpc.Events(context.Background(), &commonpb.Empty{})
	if err != nil {
		fmt.Printf(util.RPCError+"%s\n", err)
		return
	}

	for !isDone(events.Context()) {
		event, err := events.Recv()
		if err != nil {
			fmt.Printf(util.RPCError + tui.Dim(" server ") + tui.Red(err.Error()) + "\n")
			continue
		}

		switch event.EventType {
		case consts.CanaryEvent:
			fmt.Printf("\n\n") // Clear screen a bit before announcing shitty news
			fmt.Printf(util.Warn+tui.BOLD+"WARNING: %s%s has been burned (DNS Canary)\n", tui.RESET, event.Session.Name)
			sessions := getSessionsByName(event.Session.Name, transport.RPC)
			for _, session := range sessions {
				fmt.Printf("\t🔥 Session #%d is affected\n", session.ID)
			}
			fmt.Println()
			shell.RefreshMultiline(promptRender(), true, 0, false)

		case consts.JobStoppedEvent:
			cctx.Context.Jobs-- // Decrease context jobs counter
			job := event.Job
			fmt.Printf(util.Info+"Job #%d stopped (%s/%s)\n", job.ID, job.Protocol, job.Name)
			shell.RefreshMultiline(promptRender(), true, 0, false)

		case consts.SessionOpenedEvent:
			cctx.Context.Slivers++ // Decrease context slivers counter
			session := event.Session
			// The HTTP session handling is performed in two steps:
			// - first we add an "empty" session
			// - then we complete the session info when we receive the Register message from the Sliver
			// This check is here to avoid displaying two sessions events for the same session
			if session.OS != "" {
				currentTime := time.Now().Format(time.RFC1123)
				fmt.Printf("\n\n") // Clear screen a bit before announcing the king
				fmt.Printf(util.Info+"Session #%d %s - %s (%s) - %s/%s - %v\n\n",
					session.ID, session.Name, session.RemoteAddress, session.Hostname, session.OS, session.Arch, currentTime)
			}
			shell.RefreshMultiline(promptRender(), true, 0, false)

		case consts.SessionUpdateEvent:
			session := event.Session
			currentTime := time.Now().Format(time.RFC1123)
			fmt.Printf("\n") // Clear screen a bit before announcing the king
			fmt.Printf(util.Info+"Session #%d has been updated - %v\n\n", session.ID, currentTime)
			shell.RefreshMultiline(promptRender(), true, 0, false)

		case consts.SessionClosedEvent:
			cctx.Context.Slivers-- // Decrease context slivers counter
			session := event.Session
			// We print a message here if its not about a session we killed ourselves, and adapt prompt
			if cctx.Context.Sliver != nil && session.ID != cctx.Context.Sliver.ID {
				fmt.Printf("\n\n") // Clear screen a bit before announcing the king
				fmt.Printf(util.Warn+"Lost session #%d %s - %s (%s) - %s/%s\n",
					session.ID, session.Name, session.RemoteAddress, session.Hostname, session.OS, session.Arch)
				shell.RefreshMultiline(promptRender(), true, 0, false)

			} else if cctx.Context.Sliver == nil {
				fmt.Printf(util.Warn+"Lost session #%d %s - %s (%s) - %s/%s\n",
					session.ID, session.Name, session.RemoteAddress, session.Hostname, session.OS, session.Arch)
				// l.shell.RefreshMultiline(l.promptRender(), 0, false)
			} else {
				// If we have disconnected our own context, we have a 1 sec timelapse to wait for this message.
				time.Sleep(time.Millisecond * 200)
				fmt.Printf("\n" + util.Warn + " Active session disconnected")
			}
			fmt.Println()
		}
	}
}

var logrusPrintLevels = map[logrus.Level]string{
	logrus.TraceLevel: fmt.Sprintf("%s[t] %s", tui.DIM, tui.RESET),
	logrus.DebugLevel: fmt.Sprintf("%s%s[_] %s", tui.DIM, tui.BLUE, tui.RESET),
	logrus.InfoLevel:  util.Info,
	logrus.WarnLevel:  util.Warn,
	logrus.ErrorLevel: util.Error,
}

func isDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// getSessionsByName - Return all sessions for an Implant by name
func getSessionsByName(name string, rpc rpcpb.SliverRPCClient) []*clientpb.Session {
	sessions, err := rpc.GetSessions(context.Background(), &commonpb.Empty{})
	if err != nil {
		return nil
	}
	matched := []*clientpb.Session{}
	for _, session := range sessions.GetSessions() {
		if session.Name == name {
			matched = append(matched, session)
		}
	}
	return matched
}