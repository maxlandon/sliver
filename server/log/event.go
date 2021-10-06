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
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/sirupsen/logrus"
)

var (
	// PublishLogEvent - This function is being assigned by the core package
	// at startup time. This is needed to solve a circular import problem.
	PublishLogEvent func(event *clientpb.Event)
)

// ClientLogger - Create a new logger that will be passed down the
// call chain of the major components and commands through Sliver.
// The name passed as argument will be the most basic name printed in
// clients, along with the message itself.
func ClientLogger(clientID, name string) (log *logrus.Entry) {
	logger := rootLogger()
	logger.AddHook(&ClientHook{
		clientID: clientID,
	})
	return logger.WithField("name", name)
}

// ClientHook - A hook pushing logs as events to user clients
type ClientHook struct {
	clientID  string
	sessionID string
}

// Fire - Implements the fire method of the Logrus hook
func (h *ClientHook) Fire(entry *logrus.Entry) error {

	event := &clientpb.Event{
		Type:    clientpb.EventType_Log,
		Name:    entry.Data["name"].(string), // Risky, but the named logger always has a name
		Level:   h.pbLevel(entry.Level),
		Data:    []byte(entry.Message),
		Session: &clientpb.Session{UUID: h.sessionID},
		Client:  &clientpb.Client{ID: h.clientID},
	}

	// SessionID might be added at some point in the lifetime
	// of this entry, so check every call for it if we don't have it
	if h.sessionID == "" {
		if sessionID, yes := entry.Data["sessionID"]; yes {
			h.sessionID = sessionID.(string)
			event.Session = &clientpb.Session{UUID: h.sessionID}
		}
	}

	// Component need (with field)
	if component, yes := entry.Data["component"]; yes {
		event.Component = component.(string)
	}

	// Publish the event
	PublishLogEvent(event)

	return nil
}

// Levels - Hook all levels
func (h *ClientHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *ClientHook) pbLevel(level logrus.Level) clientpb.Level {
	switch level {
	case logrus.TraceLevel:
		return clientpb.Level_TRACE
	case logrus.DebugLevel:
		return clientpb.Level_DEBUG
	case logrus.InfoLevel:
		return clientpb.Level_INFO
	case logrus.WarnLevel:
		return clientpb.Level_WARNING
	case logrus.ErrorLevel:
		return clientpb.Level_ERROR
	default:
		return clientpb.Level_INFO
	}
}
