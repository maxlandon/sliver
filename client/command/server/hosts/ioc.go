package hosts

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
	"github.com/bishopfox/sliver/client/util"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// IOCs - Manage the list of IOCs for hosts
type IOCs struct{}

// Execute - Manage the list of IOCs for hosts
func (i *IOCs) Execute(args []string) (err error) {
	allHosts, err := transport.RPC.Hosts(context.Background(), &commonpb.Empty{})
	if err != nil {
		return log.Error(err)
	}

	if len(allHosts.Hosts) == 0 {
		log.Infof("No hosts (and no IOCs) in database")
		return
	}

	var noIOCs = true
	for _, host := range allHosts.Hosts {
		if len(host.IOCs) > 0 {
			noIOCs = false
			break
		}
	}

	if noIOCs {
		log.Infof("No IOCs for any hosts currently in database")
		return
	}

	displayIOCs(allHosts.Hosts)
	return
}

func displayIOCs(hosts []*clientpb.Host) {

	for _, host := range hosts {
		if len(host.IOCs) == 0 {
			log.Infof("No IOCs tracked on host")
			continue
		}

		hostTitle := fmt.Sprintf("%s%s%s (%s)%s", readline.BOLD, readline.YELLOW, host.HostUUID, host.OSVersion, readline.RESET)

		table := util.NewTable(hostTitle)
		headers := []string{"File Path", "SHA-256"}
		headLen := []int{15, 0}
		table.SetColumns(headers, headLen)

		for _, ioc := range host.IOCs {
			table.AppendRow([]string{ioc.Path, ioc.FileHash})
		}

		table.Output()
	}
}
