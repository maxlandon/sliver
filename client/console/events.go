package console

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
	"strconv"
	"strings"
	"time"

	"github.com/desertbit/go-shlex"
	"google.golang.org/protobuf/proto"

	"github.com/bishopfox/sliver/client/command/c2"
	"github.com/bishopfox/sliver/client/completion"
	consts "github.com/bishopfox/sliver/client/constants"
	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/prelude"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
)

// eventLoop - Print events coming from the server
func eventLoop(rpc rpcpb.SliverRPCClient) {

	console := core.Console

	// Call the server events stream.
	events, err := rpc.Events(context.Background(), &commonpb.Request{
		ClientID: core.ClientID,
	})
	if err != nil {
		fmt.Printf(Error+"%s\n", err)
		return
	}

	for !isDone(events.Context()) {
		event, err := events.Recv()
		if err != nil {
			fmt.Printf(Warning + "It seems that the Sliver Server disconnected, falling back...\n")
			return
		}

		switch event.EventType {

		// Operators ---------------------------------------------------------------------------------
		case consts.JoinedEvent:
			joined := fmt.Sprintf(Woot+"%s has joined the game\n", event.Client.Operator.Name)
			// joined := fmt.Sprintf("%s has joined the game", event.Client.Operator.Name)
			// joined := fmt.Sprintf("%s has joined the game\n\n", event.Client.Operator.Name)
			console.RefreshPromptLog(joined)
		case consts.LeftEvent:
			left := fmt.Sprintf(Info+"%s left the game\n", event.Client.Operator.Name)
			// left := fmt.Sprintf("%s left the game\n\n", event.Client.Operator.Name)
			console.RefreshPromptLog(left)

			// Jobs --------------------------------------------------------------------------------------
		case consts.JobStoppedEvent:
			job := event.Job
			line := fmt.Sprintf(Info+"Job #%s stopped (%s %s)\n", c2.GetShortID(job.ID), job.Profile.C2.String(), job.Profile.Hostname)
			console.RefreshPromptLog(line)

			// OPSEC -------------------------------------------------------------------------------------
		case consts.CanaryEvent:
			fmt.Printf("\n\n") // Clear screen a bit before announcing shitty news
			fmt.Printf(Warning+"WARNING: %s%s has been burned (DNS Canary)\n", normal, event.Session.Name)
			sessions := core.GetSessionsByName(event.Session.Name, transport.RPC)
			var alert string
			for _, session := range sessions {
				alert += fmt.Sprintf("\t🔥 Session #%d is affected\n", session.ID)
			}
			console.RefreshPromptLog(alert)

		case consts.WatchtowerEvent:
			msg := string(event.Data)
			fmt.Printf(Warning+"WARNING: %s%s has been burned (seen on %s)\n", normal, event.Session.Name, msg)
			sessions := core.GetSessionsByName(event.Session.Name, transport.RPC)
			var alert string
			for _, session := range sessions {
				alert += fmt.Sprintf("\t🔥 Session #%d is affected\n", session.ID)
			}
			console.RefreshPromptLog(alert)

			// Sessions ---------------------------------------------------------------------------------
		case consts.SessionOpenedEvent:
			session := event.Session

			// Create a new session data cache for completions
			completion.Cache.AddSessionCache(session)

			// Clear the screen
			fmt.Print(seqClearScreenBelow)

			// And print the event to the console
			var news string
			currentTime := time.Now().Format(time.RFC1123)
			news += fmt.Sprintf("\n\n") // Clear screen a bit before announcing the king
			news += fmt.Sprintf(Info+"Session #%d %s - %s (%s) - %s/%s - %v\n\n",
				session.ID, session.Name, session.RemoteAddress, session.Hostname, session.OS, session.Arch, currentTime)
			// Finally, update the console
			prompt := console.CurrentMenu().Prompt.Render()
			console.RefreshPromptCustom(news, prompt, 0)

			// Prelude Operator
			if prelude.SessionMapper != nil {
				err = prelude.SessionMapper.AddSession(session)
				if err != nil {
					failed := fmt.Sprintf("Could not add session to Operator: %s", err)
					console.RefreshPromptLog(failed)
				}
			}

		case consts.SessionUpdateEvent:
			session := event.Session
			currentTime := time.Now().Format(time.RFC1123)
			updated := fmt.Sprintf(Info+"Session #%d has been updated - %v\n", session.ID, currentTime)

			var id uint32
			if core.ActiveTarget.IsSession() {
				sid, _ := strconv.Atoi(core.ActiveTarget.ID())
				id = uint32(sid)
			}
			// if core.ActiveTarget.Beacon != nil {
			//         bid, _ := strconv.Atoi(core.ActiveTarget.Beacon.ID)
			//         id = uint32(bid)
			// }

			if id == session.ID {
				prompt := console.CurrentMenu().Prompt.Render()
				console.RefreshPromptCustom(updated, prompt, 0)
			} else {
				console.RefreshPromptLog(updated)
			}

		case consts.SessionClosedEvent:
			session := event.Session
			var lost string

			var id uint32
			if core.ActiveTarget.IsSession() {
				sid, _ := strconv.Atoi(core.ActiveTarget.ID())
				id = uint32(sid)
			}
			// if core.ActiveTarget.Beacon != nil {
			//         bid, _ := strconv.Atoi(core.ActiveTarget.Beacon.ID)
			//         id = uint32(bid)
			// }

			// If the session is our current session, we notify the console
			if id == session.ID {
				core.UnsetActiveSession()
			}

			// We print a message here if its not about a session we killed ourselves, and adapt prompt
			lost += fmt.Sprintf(Warning+"Lost session #%d %s - %s (%s) - %s/%s\n",
				session.ID, session.Name, session.RemoteAddress, session.Hostname, session.OS, session.Arch)
			console.RefreshPromptLog(lost)

			// In any case, delete the completion data cache for the session, if any.
			completion.Cache.RemoveSessionData(session)

			if prelude.SessionMapper != nil {
				err = prelude.SessionMapper.RemoveSession(session)
				if err != nil {
					failed := fmt.Sprintf("Could not remove session from Operator: %s", err)
					console.RefreshPromptLog(failed)
				}
				removed := fmt.Sprintf("Removed session %s from Operator\n", session.Name)
				console.RefreshPromptLog(removed)
			}

			// Beacons ---------------------------------------------------------------------------------
		case consts.BeaconRegisteredEvent:
			beacon := &clientpb.Beacon{}
			proto.Unmarshal(event.Data, beacon)
			currentTime := time.Now().Format(time.RFC1123)
			shortID := strings.Split(beacon.ID, "-")[0]

			news := fmt.Sprintf("\n\n") // Clear screen a bit before announcing the king
			news += fmt.Sprintf("Beacon #%s %s - %s (%s) - %s/%s - %v\n\n",
				shortID, beacon.Name, beacon.RemoteAddress, beacon.Hostname, beacon.OS, beacon.Arch, currentTime)
			prompt := console.CurrentMenu().Prompt.Render()
			console.RefreshPromptCustom(news, prompt, 0)

		case consts.BeaconTaskResultEvent:
			core.TriggerBeaconTaskCallback(event.Data)
		}

		// For all events, trigger reactions. These will not happen
		// if none have been registered for the event we just processed here.
		triggerReactions(event)
	}
}

func triggerReactions(event *clientpb.Event) {
	reactions := core.Reactions.On(event.EventType)
	if len(reactions) == 0 {
		return
	}

	// We need some special handling for SessionOpenedEvent to
	// set the new session as the active session
	currentActiveSession := core.ActiveTarget.Session()
	if currentActiveSession != nil {
		defer core.ActiveTarget.SetSession(currentActiveSession) // No need to update menus
		// defer con.ActiveTarget.Set(currentActiveSession, nil)
	}

	// Set the newly registered session as active, without modifying the menus and such
	core.ActiveTarget.SetSession(nil) // Unload them first
	// core.ActiveTarget.SetBeacon(nil) // Unload them first
	if event.EventType == consts.SessionOpenedEvent {
		core.ActiveTarget.SetSession(event.Session)
	}

	// Execute each reaction
	for _, reaction := range reactions {
		for _, line := range reaction.Commands {
			log.Infof("Execute reaction: '%s'\n", line)

			// Check arguments
			args, err := shlex.Split(line, true)
			if err != nil {
				log.Errorf("Reaction command has invalid args: %s", err)
				continue
			}

			// And execute through console
			_, err = core.Console.CommandParser().ParseArgs(args)
			// err = con.App.RunCommand(args)
			if err != nil {
				log.Errorf("Reaction command error: %s", err)
			}
		}
	}
}
