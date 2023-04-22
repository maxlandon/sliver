package hosts

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
	"context"

	"github.com/spf13/cobra"

	"github.com/bishopfox/sliver/client/console"
	"github.com/bishopfox/sliver/client/log"
)

// HostsIOCRmCmd - Remove a host from the database
func HostsIOCRmCmd(cmd *cobra.Command, args []string) {
	con := console.Client

	host, err := SelectHost(con)
	if err != nil {
		log.Errorf("%s\n", err)
		return
	}
	ioc, err := SelectHostIOC(host, con)
	if err != nil {
		log.Errorf("%s\n", err)
		return
	}
	_, err = con.Rpc.HostIOCRm(context.Background(), ioc)
	if err != nil {
		log.Errorf("%s\n", err)
		return
	}
	log.Infof("Removed host from database\n")
}
