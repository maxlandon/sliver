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
	"errors"
	"fmt"
	"io/ioutil"

	"github.com/maxlandon/gonsole"
	"github.com/maxlandon/readline"
	"github.com/sirupsen/logrus"

	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
)

const (
	eventBufferDefault = 200
)

var (
	// ClientLogger - Logger used by console binary components only,
	// like the client-specific part of shell tunnels.
	ClientLogger = NewClientLogger("client")

	// References to console components, used by all loggers.
	console *gonsole.Console

	// Loggers - All instantiated loggers on the client console.
	Loggers = map[string]*logrus.Logger{}

	// Mappings between logrus log levels and their associated console print icon.
	logrusPrintLevels = map[logrus.Level]string{
		logrus.TraceLevel: fmt.Sprintf("%s[T] %s", readline.BACKDARKGRAY, readline.RESET),
		logrus.DebugLevel: fmt.Sprintf("%s%s[D] %s", readline.DIM, readline.DIM, readline.RESET),
		logrus.InfoLevel:  info,
		logrus.WarnLevel:  warn,
		logrus.ErrorLevel: errror,
	}
)

// Init - The client starts monitoring all event logs coming from itself, or the server
func Init(c *gonsole.Console, rpc rpcpb.SliverRPCClient) error {
	if transport.RPC == nil {
		return errors.New("No connected RPC client")
	}
	// Keep references for loggers
	console = c

	return nil
}

// NewClientLogger - A text logger being passed to any component
// running on the client binary (only) for logging events/info.
func NewClientLogger(name string) *logrus.Logger {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	logger.Out = ioutil.Discard

	// Text hook
	clientHook := &clientHook{name: name}
	logger.AddHook(clientHook)

	// Add log to list of existing loggers, so that the user
	// can set the logging level for each of them independently.
	Loggers[name] = logger

	return logger
}

// Client Components use this hook to get their logs dispatched.
type clientHook struct {
	name string // (comm, module, etc.)
}

// All logs happening within the client binary use a classic text logger,
// which push the log messages to their appropriate channels.
func (l *clientHook) Fire(log *logrus.Entry) (err error) {

	// Get the component name, and dispatch to central log printer.
	component, ok := log.Data[l.name].(string)
	if !ok {
		component = l.name
	}

	// Final status line to be printed
	var line string

	// Surround with empty line if important
	if _, yes := log.Data["important"]; yes {
		line = line + "\n"
	}

	// Status level printing
	line = logrusPrintLevels[log.Level]

	// Print the component name in red if error
	if log.Level == logrus.ErrorLevel {
		line += fmt.Sprintf("%s%-10v %s-%s %s \n",
			readline.RED, component, readline.DIM, readline.RESET, log.Message)
	} else {
		line += fmt.Sprintf("%s%-10v %s-%s %s \n",
			readline.DIM, component, readline.DIM, readline.RESET, log.Message)
	}

	// Surround with empty line if important
	if _, yes := log.Data["important"]; yes {
		line = line + "\n"
	}

	// If we are in the middle of a command, we just print the log without refreshing prompt
	// Else, we pass the log to the shell, which will handle wrapping computing, and so on.
	// The gonsole.Console takes care of print synchronicity.
	console.RefreshPromptLog(line)

	return nil
}

// Levels - Function needed to implement the logrus.TxtLogger interface
func (l *clientHook) Levels() (levels []logrus.Level) {
	return logrus.AllLevels
}
