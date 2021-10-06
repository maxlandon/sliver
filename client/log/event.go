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
	"fmt"
	"io/ioutil"

	"github.com/maxlandon/readline"
	"github.com/sirupsen/logrus"

	"github.com/bishopfox/sliver/protobuf/clientpb"
)

var (
	// Levels - Mappings between clientpb.LogLevels and their associated logrus functions
	Levels = map[clientpb.Level]func(format string, args ...interface{}){
		clientpb.Level_TRACE:   logrus.Tracef,
		clientpb.Level_DEBUG:   logrus.Debugf,
		clientpb.Level_INFO:    logrus.Infof,
		clientpb.Level_WARNING: logrus.Warnf,
		clientpb.Level_ERROR:   logrus.Errorf,
		// Trick: fatal is used as success not possible
		clientpb.Level_SUCCESS: logrus.Infof,
	}
)

// NewEventLogger - A text logger used to print events coming from the server
func NewEventLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	logger.Out = ioutil.Discard

	// Text hook
	clientHook := &eventHook{}
	logger.AddHook(clientHook)

	// Add log to list of existing loggers, so that the user
	// can set the logging level for each of them independently.
	Loggers["events"] = logger

	return logger
}

// Client Components use this hook to get their logs dispatched.
type eventHook struct {
}

// All logs happening within the client binary use a classic text logger,
// which push the log messages to their appropriate channels.
func (l *eventHook) Fire(log *logrus.Entry) (err error) {

	// Get the component name, and dispatch to central log printer.
	component, ok := log.Data["component"].(string)
	if !ok {
		component, ok = log.Data["name"].(string)
		if !ok {
			component = ""
		}
	}

	// Maybe can switch on different printing behavior depending on name & component.

	// Final status line to be printed
	line := logrusPrintLevels[log.Level]

	// Print the component name in red if error
	if log.Level == logrus.ErrorLevel {
		if component != "" {
			line += fmt.Sprintf("%s%-10v %s-%s %s \n",
				readline.RED, component, readline.DIM, readline.RESET, log.Message)
		} else {
			line += fmt.Sprintf("%s%s %s \n",
				readline.DIM, readline.RESET, log.Message)
		}
	} else {
		if component != "" {
			line += fmt.Sprintf("%s%-10v %s-%s %s \n",
				readline.DIM, component, readline.DIM, readline.RESET, log.Message)
		} else {
			line += fmt.Sprintf("%s%s %s \n",
				readline.DIM, readline.RESET, log.Message)
		}
	}

	// If we are in the middle of a command, we just print the log without refreshing prompt
	// Else, we pass the log to the shell, which will handle wrapping computing, and so on.
	// The gonsole.Console takes care of print synchronicity.
	console.RefreshPromptLog(line)

	return nil
}

// Levels - Function needed to implement the logrus.TxtLogger interface
func (l *eventHook) Levels() (levels []logrus.Level) {
	return logrus.AllLevels
}
