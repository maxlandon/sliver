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

	"github.com/bishopfox/sliver/client/core"
	clientLog "github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
	"github.com/maxlandon/readline"
	"github.com/sirupsen/logrus"
)

// eventLoop - Print events coming from the server
func eventLoopAlt(rpc rpcpb.SliverRPCClient) {

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
		var autoLevel = clientLog.Levels[event.Level]

		// Handle the event with the logger, optionnally overriding log settings.
		handleEvent(event, log, autoLevel)
	}
}

// handleEvent - Given an event coming from the server and a logger configured with the available info, either
// use the logger itself to override the level (with all appropriate functions) or use the automatic one: autoLevel.
func handleEvent(event *clientpb.Event, log *logrus.Entry, autoLevel func(format string, args ...interface{})) {

	// Adapt behavior and message based on type.
	switch event.Type {

	// Generic Log events
	case clientpb.EventType_Log:

	// Operators Events
	case clientpb.EventType_UserJoined:
		log.Infof("%s has joined the game", event.Client.Operator.Name)
	case clientpb.EventType_UserLeft:
		log.Infof("%s left the game", event.Client.Operator.Name)

	// OPSEC Events
	case clientpb.EventType_CanaryBurned, clientpb.EventType_Watchtower:
		handleEventOpsec(event, log, autoLevel)

	// Session Events
	case clientpb.EventType_SessionOpened, clientpb.EventType_SessionUpdated, clientpb.EventType_SessionClosed:
		handleEventSession(event, log, autoLevel)

	// Beacon Events
	case clientpb.EventType_BeaconRegistered, clientpb.EventType_BeaconTaskResult:
		handleEventBeacon(event, log, autoLevel)
	}

}

// handleEventOpsec - Display an opsec event.
func handleEventOpsec(event *clientpb.Event, log *logrus.Entry, autoLevel func(format string, args ...interface{})) {
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

	switch event.Type {
	case clientpb.EventType_SessionOpened:
	case clientpb.EventType_SessionUpdated:
	case clientpb.EventType_SessionClosed:
	}
}

// handleEventBeacon - Display a beacon event
func handleEventBeacon(event *clientpb.Event, log *logrus.Entry, autoLevel func(format string, args ...interface{})) {
}
