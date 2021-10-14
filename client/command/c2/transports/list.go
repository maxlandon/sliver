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
	"sort"
	"strconv"
	"time"

	"github.com/acarl005/stripansi"
	"github.com/maxlandon/readline"

	"github.com/bishopfox/sliver/client/command/c2"
	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/client/util"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// List - List all or some C2 transports for the current session or context
type List struct {
	Args struct {
		TransportID []string `description:"(optional) one or more malleable C2 transports to list only"`
	} `positional-args:"yes"`
}

// Execute - List all or some C2 transports
func (l *List) Execute(args []string) (err error) {

	transports, err := transport.RPC.GetTransports(context.Background(), &sliverpb.TransportsReq{
		Request: core.ActiveTarget.Request(),
	})
	if err != nil {
		return log.Error(err)
	}
	var filtered []*sliverpb.Transport
	for _, id := range l.Args.TransportID {
		for _, transport := range transports.Transports {
			if c2.GetShortID(transport.ID) == id {
				filtered = append(filtered, transport)
			}
		}
	}

	var list = []*sliverpb.Transport{}
	if len(filtered) > 0 {
		list = filtered
	} else {
		list = transports.Transports
	}

	printTransports(list)

	return
}

func printTransports(transports []*sliverpb.Transport) {

	table := util.NewTable("")
	headers := []string{"State", "N°", "ID", "Type", "C2", "Address", "Errs/Reconnect", "Jit/Interval", "Comms", "try/fail"}
	headLen := []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	table.SetColumns(headers, headLen)

	// Sort the transports by priority
	var keys []int
	for _, t := range transports {
		keys = append(keys, int(t.Order))
	}
	sort.Ints(keys)

	// Get padding for transports
	var padd int
	for _, transport := range transports {
		if len(stripansi.Strip(c2.TransportConnection(transport, 0))) > padd {
			padd = len(stripansi.Strip(c2.TransportConnection(transport, padd)))
		}
	}

	for _, v := range keys {
		for _, transport := range transports {
			if int(transport.Order) != v {
				continue
			}

			prof := transport.Profile

			var state string
			if transport.Running {
				state = readline.Bold(readline.Green("Active"))
			} else {
				state = readline.Dim("Loaded")
			}
			order := readline.Dim(strconv.Itoa(int(transport.Order)))
			id := c2.GetShortID(transport.ID)
			channel := prof.C2.String()
			c2Type := prof.Type.String()
			address := c2.TransportConnection(transport, padd)

			// Timeouts
			var timeouts string
			var jitInt string
			if prof.Type == sliverpb.C2Type_Beacon {
				jitInt = fmt.Sprintf("%-3s / %3s", time.Duration(prof.Jitter), time.Duration(prof.Interval))
				timeouts = fmt.Sprintf("%d / %ss", prof.MaxConnectionErrors, time.Duration(prof.Interval))
			} else {
				timeouts = fmt.Sprintf("%-4d / %4s", prof.MaxConnectionErrors, time.Duration(prof.Interval))
			}

			// Comm
			var comms string
			if prof.CommDisabled {
				comms = "no"
			} else {
				comms = "yes"
			}

			// Attempts
			var attempts string
			if (transport.Attempts == transport.Failures) && transport.Attempts == prof.MaxConnectionErrors {
				attempts = readline.BOLD + readline.RED
			} else if transport.Failures == 0 && transport.Attempts > 0 {
				attempts = readline.GREEN
			} else if transport.Failures > 0 {
				attempts = readline.BOLD + readline.YELLOW
			} else if transport.Failures > 1 {
				attempts = readline.YELLOW
			}
			attempts = attempts + fmt.Sprintf("%d / %d", transport.Attempts, transport.Failures)

			// Add to table
			table.AppendRow([]string{state, order, id, c2Type, channel, address, timeouts, jitInt, comms, attempts})
		}
	}

	fmt.Printf(table.Output())
}
