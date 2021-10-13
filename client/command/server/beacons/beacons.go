package beacons

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

	"github.com/bishopfox/sliver/client/command/c2"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/client/util"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// Main & Sliver context available commands
// ----------------------------------------------------------------------------------------------------------

// Beacons - Root command for managing beacons. Prints registered beacons by default.
type Beacons struct{}

// Execute - Prints registered beacons if no sub commands invoked.
func (s *Beacons) Execute(args []string) (err error) {

	// Get a map of all beacons
	beacons, err := transport.RPC.GetBeacons(context.Background(), &commonpb.Empty{})
	if err != nil {
		return log.Error(err)
	}
	beaconsMap := map[string]*clientpb.Beacon{}
	for _, beacon := range beacons.GetBeacons() {
		beaconsMap[beacon.ID] = beacon
	}

	// Print all beacons
	if 0 < len(beaconsMap) {
		printBeacons(beaconsMap)
	} else {
		log.Infof("No beacons")
	}

	return
}

func printBeacons(beacons map[string]*clientpb.Beacon) {

	// Sort keys
	var keys []string
	for k := range beacons {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	table := util.NewTable("")
	headers := []string{"ID", "Name", "Tasks", "Transport", "Remote Address", "User", "Hostname", "OS/Arch", "Last Check-in", "Next Check-in"}
	headLen := []int{0, 0, 0, 0, 15, 0, 0, 0, 0, 0}
	table.SetColumns(headers, headLen)

	for _, k := range keys {
		b := beacons[k]
		tasks := fmt.Sprintf("%d / %d", b.TasksCountCompleted, b.TasksCount)
		osArch := fmt.Sprintf("%s/%s", b.OS, b.Arch)

		transport := b.Transport.Profile.C2.String()
		addr := b.Transport.RemoteAddress
		row := []string{c2.GetShortID(b.ID), b.Name, tasks, transport, addr, b.Username,
			b.Hostname, osArch, strconv.Itoa(int(b.LastCheckin)), strconv.Itoa(int(b.NextCheckin))}

		table.AppendRow(row)
	}
	fmt.Printf(table.Output())
}
