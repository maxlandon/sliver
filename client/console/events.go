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
	"time"

	"github.com/bishopfox/sliver/client/command/c2"
	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	clientLog "github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/prelude"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/desertbit/go-shlex"
	"github.com/maxlandon/readline"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

// eventLoop - Print events coming from the server
func eventLoop(rpc rpcpb.SliverRPCClient) {

	// console := core.Console

	// Call the server events stream.
	events, err := rpc.Events(context.Background(), &commonpb.Request{
		ClientID: core.ClientID,
	})
	if err != nil {
		fmt.Printf(Error+"%s\n", err)
		return
	}

	// Set up the client logger in charge of formatting and displaying events
	logger := clientLog.NewEventLogger()

	// For each event and as long as the stream holds
	for !isDone(events.Context()) {
		event, err := events.Recv()
		if err != nil {
			fmt.Printf(Warning + "It seems that the Sliver Server disconnected, falling back...\n")
			return
		}

		// Create a log entry, and populate most of the fields of the logger first
		var log *logrus.Entry
		log = logger.WithField("name", event.Name)
		if event.Component != "" {
			log = logger.WithField("component", event.Component)
		}
		var autoLevel = clientLog.AutoLogLevel(log, event.Level)

		// Handle the event with the logger, optionnally overriding log settings.
		handleEvent(event, log, autoLevel)
	}
}

// handleEvent - Given an event coming from the server and a logger configured with the available info, either
// use the logger itself to override the level (with all appropriate functions) or use the automatic one: autoLevel.
func handleEvent(event *clientpb.Event, log *logrus.Entry, autoLog func(format string, args ...interface{})) {

	// Adapt behavior and message based on type.
	switch event.Type {

	// Generic Log events
	case clientpb.EventType_Log:
		handleEventLog(event, log, autoLog)

	// Operators Events
	case clientpb.EventType_UserJoined:
		log.Infof("%s has joined the game", event.Client.Operator.Name)
	case clientpb.EventType_UserLeft:
		log.Infof("%s left the game", event.Client.Operator.Name)

	// OPSEC Events
	case clientpb.EventType_CanaryBurned, clientpb.EventType_Watchtower:
		handleEventOpsec(event, log, autoLog)

	// Session Events
	case clientpb.EventType_SessionOpened, clientpb.EventType_SessionUpdated, clientpb.EventType_SessionClosed:
		handleEventSession(event, log, autoLog)

	// Beacon Events
	case clientpb.EventType_BeaconRegistered, clientpb.EventType_BeaconTaskResult:
		handleEventBeacon(event, log, autoLog)
	}

	//                 case consts.JobStoppedEvent:
	//                         job := event.Job
	//                         line := fmt.Sprintf(Info+"Job #%s stopped (%s %s)\n", c2.GetShortID(job.ID), job.Profile.C2.String(), job.Profile.Hostname)
	//                         console.RefreshPromptLog(line)
	//
	// For all events, trigger reactions. These will not happen
	// if none have been registered for the event we just processed here.
	triggerReactions(event)
}

// handleEventLog - Display a generic log event. Might be thrown by any component server side, either targetin a session,
// a client or both. We aim to make as good discretionnary choices as possible when deciding when to print when not, in
// addition to the console current log level for those components.
func handleEventLog(event *clientpb.Event, log *logrus.Entry, autoLog func(format string, args ...interface{})) {
	autoLog(string(event.Data))
}

// handleEventOpsec - Display an opsec event.
func handleEventOpsec(event *clientpb.Event, log *logrus.Entry, autoLevel func(format string, args ...interface{})) {

	// For all OPSEC message, add one empty line before and after the log
	log = log.WithField("important", true)

	switch event.Type {

	// Canaries
	case clientpb.EventType_CanaryBurned:
		message := fmt.Sprintf("%s%s has been burned (DNS Canary)%s", readline.YELLOW, event.Session.Name, readline.YELLOW)
		sessions := core.GetSessionsByName(event.Session.Name, transport.RPC)
		var alert string
		for _, session := range sessions {
			alert += fmt.Sprintf("\n\t🔥 Session #%d is affected", session.ID)
		}
		log = log.WithField("name", readline.YELLOW+"Canary"+readline.RESET)
		log.Warnf(message)

	// WatchTower
	case clientpb.EventType_Watchtower:
		msg := event.Data
		message := fmt.Sprintf("%s%s has been burned (seen on %s)%s", readline.YELLOW, event.Session.Name, msg, readline.YELLOW)
		sessions := core.GetSessionsByName(event.Session.Name, transport.RPC)
		var alert string
		for _, session := range sessions {
			alert += fmt.Sprintf("\n\t🔥 Session #%d is affected", session.ID)
		}
		log = log.WithField("name", readline.YELLOW+"WatchTower"+readline.RESET)
		log.Warnf(message)
	}
}

// handleEventSession - Display a session event
func handleEventSession(event *clientpb.Event, log *logrus.Entry, autoLevel func(format string, args ...interface{})) {

	session := event.Session
	currentTime := time.Now().Format(time.RFC1123)
	log = log.WithField("name", "sessions")

	switch event.Type {

	case clientpb.EventType_SessionOpened:
		log = log.WithField("important", true) // Add empty lines around the news

		// Clear the screen
		fmt.Print(seqClearScreenBelow)

		// And print the event to the console
		news := fmt.Sprintf("Session #%d %s - %s (%s) - %s/%s - %v",
			session.ID, session.Name, session.RemoteAddress,
			session.Hostname, session.OS, session.Arch, currentTime)

		// Finally, update the console
		log.Infof(news)

		// Prelude Operator
		if prelude.SessionMapper != nil {
			err := prelude.SessionMapper.AddSession(session)
			if err != nil {
				failed := fmt.Sprintf("Could not add session to Operator: %s", err)
				core.Console.RefreshPromptLog(failed)
			}
		}

	case clientpb.EventType_SessionClosed:

		var lost string
		var id uint32
		if core.ActiveTarget.IsSession() {
			sid, _ := strconv.Atoi(core.ActiveTarget.ID())
			id = uint32(sid)
		}
		// if core.ActiveTarget.Beacon != nil {
		//         bid, _ := strconv.Atoi(core.ActiveTarget.Beacon.ID)
		//         id = core.GetShortID()
		// }

		// If the session is our current session, we notify the console
		if id == session.ID {
			core.UnsetActiveSession()
		}

		// We print a message here if its not about a session we killed ourselves, and adapt prompt
		lost += fmt.Sprintf("Lost session #%d %s - %s (%s) - %s/%s",
			session.ID, session.Name, session.RemoteAddress,
			session.Hostname, session.OS, session.Arch)
		log.Warnf(lost)

		if prelude.SessionMapper != nil {
			err := prelude.SessionMapper.RemoveSession(session)
			if err != nil {
				log.Errorf("Could not remove session from Operator: %s", err)
			}
			log.Infof("Removed session %s from Operator\n", session.Name)
		}

	case clientpb.EventType_SessionUpdated:
		updated := fmt.Sprintf("Session #%d has been updated - %v", session.ID, currentTime)
		log.Infof(updated)

	}
}

// handleEventBeacon - Display a beacon event
func handleEventBeacon(event *clientpb.Event, log *logrus.Entry, autoLevel func(format string, args ...interface{})) {

	log = log.WithField("name", "beacons")

	switch event.Type {

	case clientpb.EventType_BeaconRegistered:
		log = log.WithField("important", true) // Add empty lines around the news
		beacon := &clientpb.Beacon{}
		proto.Unmarshal(event.Data, beacon)
		currentTime := time.Now().Format(time.RFC1123)

		news := fmt.Sprintf("Beacon #%s %s - %s (%s) - %s/%s - %v",
			c2.GetShortID(beacon.ID), beacon.Name, beacon.RemoteAddress,
			beacon.Hostname, beacon.OS, beacon.Arch, currentTime)
		log.Infof(news)

	case clientpb.EventType_BeaconTaskResult:
		core.TriggerBeaconTaskCallback(event.Data)
	}
}

func triggerReactions(event *clientpb.Event) {
	reactions := core.Reactions.On(event.Type.String())
	if len(reactions) == 0 {
		return
	}

	// We need some special handling for SessionOpenedEvent to
	// set the new session as the active session
	currentActiveSession := core.ActiveTarget.Session()
	if currentActiveSession != nil {
		defer core.ActiveTarget.SetSession(currentActiveSession) // No need to update menus
	}

	// Set the newly registered session as active, without modifying the menus and such
	core.ActiveTarget.SetSession(nil) // Unload them first
	// core.ActiveTarget.SetBeacon(nil) // Unload them first
	if event.Type == clientpb.EventType_SessionOpened {
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
