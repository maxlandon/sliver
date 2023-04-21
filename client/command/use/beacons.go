package use

/*
	Sliver Implant Framework
	Copyright (C) 2021  Bishop Fox

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
	"github.com/bishopfox/sliver/client/command/beacons"
	"github.com/bishopfox/sliver/client/console"
	"github.com/bishopfox/sliver/client/log"
	"github.com/spf13/cobra"
)

// UseBeaconCmd - Change the active beacon
func UseBeaconCmd(cmd *cobra.Command, args []string) {
	con := console.Client

	beacon, err := beacons.SelectBeacon(con)
	if beacon != nil {
		con.ActiveTarget.Set(nil, beacon)
		log.Infof("Active beacon %s (%s)\n", beacon.Name, beacon.ID)
	} else if err != nil {
		switch err {
		case beacons.ErrNoBeacons:
			log.Errorf("No beacon available\n")
		case beacons.ErrNoSelection:
			log.Errorf("No beacon selected\n")
		default:
			log.Errorf("%s\n", err)
		}
	}
}
