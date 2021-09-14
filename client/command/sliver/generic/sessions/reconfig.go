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
	"fmt"
	"regexp"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// Set - Set an environment value for the current session.
type Set struct {
	Options struct {
		Name      string `long:"name" description:"set agent name"`
		Reconnect int32  `long:"reconnect" short:"r" description:"reconnect interval for agent" default:"-1"`
		Poll      int32  `long:"poll" short:"p" description:"poll interval for agent" default:"-1"`
	} `group:"session values"`
}

// Execute - Set an environment value for the current session.
func (s *Set) Execute(args []string) (err error) {

	// Option to change the agent name
	name := s.Options.Name
	if name != "" {
		isAlphanumeric := regexp.MustCompile(`^[[:alnum:]]+$`).MatchString
		if !isAlphanumeric(name) {
			fmt.Printf(Error + "Name must be in alphanumeric only\n")
			return
		}
	}

	session, err := transport.RPC.UpdateSession(context.Background(), &clientpb.UpdateSession{
		SessionID:         core.ActiveSession.ID,
		Name:              name,
		ReconnectInterval: s.Options.Reconnect,
		PollInterval:      s.Options.Poll,
	})
	if err != nil {
		log.Errorf("Error: %v", err)
		return
	}
	core.ActiveTarget.Session = session // Will be noticed by all components in need.

	// For the moment, we ask the current working directory to implant...
	pwd, err := transport.RPC.Pwd(context.Background(), &sliverpb.PwdReq{
		Request: core.RequestTimeout(10),
	})
	if err != nil {
		log.Errorf("%s\n", err)
	} else {
		core.ActiveTarget.Session.WorkingDirectory = pwd.Path
	}

	return
}
