package profiles

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
	"strings"

	"github.com/maxlandon/readline"

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/client/util"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// Profiles - List saved implant profiles, and root command
type Profiles struct{}

// Execute - List saved implant profiles.
func (p *Profiles) Execute(args []string) (err error) {
	profiles, err := getSliverProfiles()
	if err != nil {
		return log.Error(err)
	}
	if len(*profiles) == 0 || profiles == nil {
		log.Infof("No profiles, create one with `profiles new`")
		return
	}
	table := util.NewTable(readline.Bold(readline.Yellow("Implant Profiles")))

	headers := []string{"Name", "OS/Arch", "Format", "C2 Transports", "Debug/Obfsc/Evasion", "Limits", "Errs/Timeout"}
	headLen := []int{0, 0, 0, 15, 20, 15, 0}
	table.SetColumns(headers, headLen)

	var keys []string
	for k := range *profiles {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Populate the table with builds
	for _, k := range keys {
		config := (*profiles)[k].Config

		osArch := fmt.Sprintf("%s/%s", config.GOOS, config.GOARCH)

		// Get a formated C2s string
		var c2s string
		if 0 < len(config.C2) {
			for index, c2 := range config.C2 {
				// for index, c2 := range config.C2[0:] {
				endpoint := fmt.Sprintf("[%d] %s \n", index+1, c2.URL)
				c2s += endpoint
			}
		}
		c2s = strings.TrimSuffix(c2s, "\n")

		// Security
		var debug, obfs, evas string
		if config.Debug {
			debug = readline.Yellow(" yes ")
		} else {
			debug = readline.Dim(" no ")
		}
		if config.ObfuscateSymbols {
			obfs = readline.Green(" yes ")
		} else {
			obfs = readline.Yellow(" no ")
		}
		if config.Evasion {
			evas = readline.Green("  yes ")
		} else {
			evas = readline.Yellow("  no ")
		}
		sec := fmt.Sprintf("%s %s %s", debug, obfs, evas)

		// Limits
		var user, domainJoin, dateTime, hostname, file string
		if config.LimitUsername != "" {
			user = readline.Bold("User: ") + config.LimitUsername + "\n"
		}
		if config.LimitHostname != "" {
			hostname = readline.Bold("Hostname: ") + config.LimitHostname + "\n"
		}
		if config.LimitFileExists != "" {
			file = readline.Bold("File: ") + config.LimitFileExists + "\n"
		}
		if config.LimitDatetime != "" {
			dateTime = readline.Bold("DateTime: ") + config.LimitDatetime + "\n"
		}
		if config.LimitDomainJoined == true {
			domainJoin = readline.Bold("Domain joined: ") + config.LimitDatetime + "\n"
		}
		limits := user + hostname + file + domainJoin + dateTime

		// Timeouts
		timeouts := fmt.Sprintf("%d / %ds", config.MaxConnectionErrors, config.ReconnectInterval)

		// Add row
		table.AppendRow([]string{k, osArch, config.Format.String(), c2s, sec, limits, timeouts})
	}

	// Print table
	table.Output()

	return
}

func getSliverProfiles() (profiles *map[string]*clientpb.ImplantProfile, err error) {
	pbProfiles, err := transport.RPC.ImplantProfiles(context.Background(), &commonpb.Empty{})
	if err != nil {
		return nil, log.Error(err)
	}
	profiles = &map[string]*clientpb.ImplantProfile{}
	for _, profile := range pbProfiles.Profiles {
		(*profiles)[profile.Name] = profile
	}
	return profiles, nil
}
