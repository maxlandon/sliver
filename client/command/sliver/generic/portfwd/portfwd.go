package portfwd

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
	"sort"
	"strconv"

	"github.com/maxlandon/readline"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/util"
)

var (
	portfwdLog = log.ClientLogger.WithField("portfwd", "portfwd")
)

// Portfwd - Port forwards mangement command; Prints them by default.
// Not that this command will only have subcommands available in the Sliver menu,
// and that this precise struct will only be assigned once in the server package.
type Portfwd struct{}

// Execute -  Print port forwarders for all sessions, and current above
func (p *Portfwd) Execute(args []string) (err error) {

	portfwds := core.Portfwds.List()
	if len(portfwds) == 0 {
		log.Infof("No port forwards\n")
		return
	}
	sort.Slice(portfwds[:], func(i, j int) bool {
		return portfwds[i].ID < portfwds[j].ID
	})

	// Table headers
	headers := []string{"ID", "Session ID", "Local Address", "Remote Address"}
	headLen := []int{5, 10, 20, 20}

	// We might use two different tables depending on if we have a current session or not.
	sessForwarders := util.NewTable(readline.Bold(readline.Blue("Current Session \n")))
	sessForwarders.SetColumns(headers, headLen)
	var sessCount int

	allForwarders := util.NewTable(readline.Bold(readline.Blue("All sessions\n")))
	allForwarders.SetColumns(headers, headLen)
	var allCount int

	// Add forwarders to their table
	for _, p := range portfwds {
		row := []string{strconv.Itoa(p.ID), strconv.Itoa(int(p.SessionID)), p.BindAddr, p.RemoteAddr}
		if core.ActiveTarget.Session() != nil && p.SessionID == core.ActiveTarget.Session().ID {
			sessForwarders.Append(row)
			sessCount++
		} else {
			allForwarders.Append(row)
			allCount++
		}
	}

	// Print any or both tables, adjusting for newlines
	if sessCount > 0 {
		sessForwarders.Output()
	}
	if allCount > 0 {
		if sessCount > 0 {
			fmt.Println()
		}
		allForwarders.Output()
	}

	return
}
