package prelude

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

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/prelude"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// Connect - Connect to Prelude's operator
type Connect struct {
	Positional struct {
		URL string `description:"preclude's Operator instance URL" required:"1-1"`
	} `positional-args:"true" required:"true"`
	Options struct {
		AESKey       string `long:"aes-key" short:"a" description:"AES Key for communication encryption"`
		SkipExisting bool   `long:"skip-existing" short:"s" description:"do not add existing sessions as Operator Agents"`
		Range        string `long:"range" short:"r" description:"agents range" `
	} `group:"loot fetch options"`
}

// Execute - Connect to Prelude's operator
func (m *Connect) Execute(args []string) (err error) {
	config := &prelude.OperatorConfig{
		Range:       m.Options.Range,
		OperatorURL: m.Positional.URL,
		RPC:         transport.RPC,
		AESKey:      m.Options.AESKey,
	}

	sessionMapper := prelude.InitSessionMapper(config)

	log.Infof("Connected to Operator at %s", m.Positional.URL)
	if !m.Options.SkipExisting {
		sessions, err := transport.RPC.GetSessions(context.Background(), &commonpb.Empty{})
		if err != nil {
			return log.Errorf("Could not get session list: %s", err)
		}
		if len(sessions.Sessions) > 0 {
			log.Infof("Adding existing sessions ...")
			for _, sess := range sessions.Sessions {
				err = sessionMapper.AddSession(sess)
				if err != nil {
					err := log.Errorf("Could not add session %s to session mapper: %s", sess.Name, err)
					fmt.Printf(err.Error())
					continue
				}
			}
			log.Infof("Done !")
		}
	}
	return
}
