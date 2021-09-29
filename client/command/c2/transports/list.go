package transports

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
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/client/util"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/maxlandon/readline"
)

// List - List all or some C2 transports for the current session or context
type List struct {
	Args struct {
		TransportID []string `description:"(optional) one or more malleable C2 transports to list only"`
	} `positional-args:"yes"`
}

// Execute - List all or some C2 transports
func (l *List) Execute(args []string) (err error) {

	transports, err := transport.RPC.GetTransports(context.Background(), &clientpb.GetTransportsReq{
		Request: core.ActiveTarget.Request(),
	})
	if err != nil {
		return log.Error(err)
	}
	var filtered []*clientpb.Transport
	for _, id := range l.Args.TransportID {
		for _, transport := range transports.Transports {
			if c2.GetShortID(transport.ID) == id {
				filtered = append(filtered, transport)
			}
		}
	}

	var list = []*clientpb.Transport{}
	if len(filtered) > 0 {
		list = filtered
	} else {
		list = transports.Transports
	}

	printTransports(list)

	return
}

func printTransports(transports []*clientpb.Transport) {

	table := util.NewTable("")
	headers := []string{"State", "Order", "ID", "Channel", "Direction", "Address", "Errs/Reconnect", "Jit/Interval", "SSH Comms"}
	headLen := []int{0, 0, 0, 0, 0, 0, 0, 0, 0}
	table.SetColumns(headers, headLen)

	for _, t := range transports {

		var state string
		if t.Running {
			state = readline.Green("Running")
		} else {
			state = readline.Dim("Available")
		}
		order := readline.Dim(strconv.Itoa(int(t.Order)))
		id := c2.GetShortID(t.ID)
		channel := t.Profile.C2.String()
		dir := t.Profile.Direction.String()
		address := readline.Bold(c2.FullTargetPath(t.Profile))

		// Timeouts
		var timeouts string
		var jitInt string
		if t.Profile.Type == sliverpb.C2Type_Beacon {
			jitInt = fmt.Sprintf("%-3s / %3s", time.Duration(t.Profile.Jitter), time.Duration(t.Profile.Interval))
			timeouts = fmt.Sprintf("%d / %ss", t.Profile.MaxConnectionErrors, time.Duration(t.Profile.Interval))
		} else {
			timeouts = fmt.Sprintf("%-4d / %4s", t.Profile.MaxConnectionErrors, time.Duration(t.Profile.Interval))
		}

		// Comm
		var comms string
		if t.Profile.CommDisabled {
			comms = readline.YELLOW + "no" + readline.RESET
		} else {
			comms = readline.GREEN + "yes" + readline.RESET
		}

		// Add to table
		table.AppendRow([]string{state, order, id, channel, dir, address, timeouts, jitInt, comms})
	}

	table.Output()
}
