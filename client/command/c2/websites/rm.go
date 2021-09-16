package websites

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

	"github.com/maxlandon/readline"

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
)

// WebsitesDelete - Remove an entire website
type WebsitesDelete struct {
	Positional struct {
		WebsiteName []string `description:"website content name to display" required:"1"`
	} `positional-args:"yes" required:"yes"`
}

// Execute - Command
func (w *WebsitesDelete) Execute(args []string) (err error) {

	for _, name := range w.Positional.WebsiteName {
		_, err := transport.RPC.WebsiteRemove(context.Background(), &clientpb.Website{
			Name: name,
		})
		if err != nil {
			err := log.Errorf("Failed to remove website %s", err)
			fmt.Printf(err.Error())
		} else {
			log.Infof("Removed website %s%s%s", readline.YELLOW, name, readline.RESET)
		}
	}
	return
}
