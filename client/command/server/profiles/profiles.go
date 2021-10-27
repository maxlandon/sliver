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
	"time"

	"github.com/maxlandon/readline"

	c2Cmds "github.com/bishopfox/sliver/client/command/c2"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/client/util"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// Profiles - List saved implant profiles, and root command
type Profiles struct{}

// Execute - List saved implant profiles.
func (p *Profiles) Execute(args []string) (err error) {
	profiles, err := getSliverProfiles()
	if err != nil {
		return log.Error(err)
	}
	if len(profiles) == 0 || profiles == nil {
		log.Infof("No profiles, create one with `profiles new`")
		return
	}
	table := util.NewTable(readline.Bold(readline.Yellow("Implant Profiles")))

	headers := []string{"Name", "OS/Arch", "Format", "Debug/Obfsc/Evasion", "Limits", "T - C2 Transport - errs/intvl/jit"}
	headLen := []int{0, 0, 0, 20, 15, 25}
	table.SetColumns(headers, headLen)

	var keys []string
	for k := range profiles {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Populate the table with builds
	for _, k := range keys {
		config := profiles[k].Config

		// Core ---------------------------
		osArch := fmt.Sprintf("%s/%s", config.GOOS, config.GOARCH)
		var format string
		switch config.Format {
		case clientpb.OutputFormat_EXECUTABLE:
			format = "exe"
		case clientpb.OutputFormat_SERVICE:
			format = "svc"
		case clientpb.OutputFormat_SHARED_LIB:
			format = "dll"
		case clientpb.OutputFormat_SHELLCODE:
			format = "shellc"
		}

		// Security ---------------------------
		var debug, obfs, evas string
		if config.Debug {
			debug = readline.Yellow("yes/")
		} else {
			debug = readline.Dim("no/")
		}
		if config.ObfuscateSymbols {
			obfs = readline.Green("yes/")
		} else {
			obfs = readline.Yellow("no/")
		}
		if config.Evasion {
			evas = readline.Green("yes")
		} else {
			evas = readline.Yellow("no")
		}
		sec := fmt.Sprintf("%s%s%s", debug, obfs, evas)

		// Limits ---------------------------
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

		// C2 Channels ---------------------------
		var c2s string
		for i, c2 := range config.C2S {
			index := readline.Dim(fmt.Sprintf("[%d]", i))
			var c2Type string
			if c2.Type == sliverpb.C2Type_Beacon {
				c2Type = readline.YELLOW + "B" + readline.RESET
			} else {
				c2Type = readline.GREEN + "S" + readline.RESET
			}
			var dir string
			if c2.Direction == sliverpb.C2Direction_Bind {
				dir = " => "
			} else {
				dir = " <= "
			}
			path := readline.Bold(readline.Blue(strings.ToLower(c2.C2.String()) + "://" + c2Cmds.FullTargetPath(c2)))

			var timeouts string
			var jitInt string
			var settings string
			if c2.Type == sliverpb.C2Type_Beacon {
				timeouts = fmt.Sprintf(" %-3d / ", c2.MaxErrors)
				jitInt = fmt.Sprintf(" %-3s/ %3s", time.Duration(c2.Interval), time.Duration(c2.Jitter))
				settings = fmt.Sprintf("%10s%s", timeouts, jitInt)
			} else {
				timeouts = fmt.Sprintf("%6d / %s", c2.MaxErrors, time.Duration(c2.Interval))
				settings = fmt.Sprintf("%14s", timeouts)
			}

			endpoint := index + c2Type + dir + path + settings + "\n"
			c2s += endpoint
		}
		c2s = strings.TrimSuffix(c2s, "\n")

		// Add row
		table.AppendRow([]string{k, osArch, format, sec, limits, c2s})
	}

	// Print table
	fmt.Printf(table.Output())

	return
}

func getSliverProfiles() (profiles map[string]*clientpb.ImplantProfile, err error) {
	pbProfiles, err := transport.RPC.ImplantProfiles(context.Background(), &commonpb.Empty{})
	if err != nil {
		return nil, log.Error(err)
	}
	profiles = map[string]*clientpb.ImplantProfile{}
	for _, profile := range pbProfiles.Profiles {
		profiles[profile.Name] = profile
	}
	return profiles, nil
}

// GetImplantProfileByName - Get a sliver implant profile
func GetImplantProfileByName(name string) (profile *clientpb.ImplantProfile, err error) {
	pbProfiles, err := transport.RPC.ImplantProfiles(context.Background(), &commonpb.Empty{})
	if err != nil {
		return nil, err
	}
	for _, profile := range pbProfiles.Profiles {
		if profile.Name == name {
			return profile, nil
		}
	}
	return nil, fmt.Errorf("Failed to find a profile matching name %s", name)
}
