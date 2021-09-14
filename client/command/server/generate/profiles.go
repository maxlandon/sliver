package generate

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
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/maxlandon/readline"

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/client/util"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// ProfilesCmd - Root profile management command
type ProfilesCmd struct {
}

// Execute - Root profile management command
func (p *ProfilesCmd) Execute(args []string) (err error) {
	return
}

// NewProfile - Configure and save a new implant profile.
type NewProfile struct {
	StageOptions // This commands works the same as generate, and needs full options.
}

// Execute - Configure and save a new implant profile.
func (p *NewProfile) Execute(args []string) (err error) {

	name := p.CoreOptions.Profile
	if name == "" {
		return log.Errorf("Invalid profile name")
	}

	config, err := parseCompileFlags(p.StageOptions)
	if err != nil {
		return log.Error(err)
	}

	profile := &clientpb.ImplantProfile{
		Name:   name,
		Config: config,
	}
	resp, err := transport.RPC.SaveImplantProfile(context.Background(), profile)

	if err != nil {
		return log.Error(err)
	}

	log.Infof("Saved new profile %s\n", resp.Name)
	return
}

// Profiles - List saved implant profiles.
type Profiles struct{}

// Execute - List saved implant profiles.
func (p *Profiles) Execute(args []string) (err error) {
	profiles, err := getSliverProfiles()
	if err != nil {
		return log.Error(err)
	}
	if len(*profiles) == 0 || profiles == nil {
		log.Infof("No profiles, create one with `profiles new`\n")
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

// ProfileGenerate - Generate implant from a profile given as argment (completed)
type ProfileGenerate struct {
	Positional struct {
		Profile string `description:"name of profile to use" required:"1-1"`
	} `positional-args:"true" required:"true"`
	Options struct {
		Save string `long:"save" short:"s" description:"directory/file where to save binary"`
	} `group:"profile options"`
}

// Execute - Generate implant from a profile given as argment (completed)
func (p *ProfileGenerate) Execute(args []string) (err error) {
	name := p.Positional.Profile
	save := p.Options.Save
	if save == "" {
		save, _ = os.Getwd()
	}
	profiles, err := getSliverProfiles()
	if err != nil {
		return log.Error(err)
	}
	if profile, ok := (*profiles)[name]; ok {
		implantFile, err := compile(profile.Config, save)
		if err != nil {
			return err
		}
		profile.Config.Name = buildImplantName(implantFile.Name)
		_, err = transport.RPC.SaveImplantProfile(context.Background(), profile)
		if err != nil {
			return log.Errorf("could not update implant profile: %v", err)
		}
	} else {
		return log.Errorf("No profile with name '%s'", name)
	}
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

func getLimitsString(config *clientpb.ImplantConfig) string {
	limits := []string{}
	if config.LimitDatetime != "" {
		limits = append(limits, fmt.Sprintf("datetime=%s", config.LimitDatetime))
	}
	if config.LimitDomainJoined {
		limits = append(limits, fmt.Sprintf("domainjoined=%v", config.LimitDomainJoined))
	}
	if config.LimitUsername != "" {
		limits = append(limits, fmt.Sprintf("username=%s", config.LimitUsername))
	}
	if config.LimitHostname != "" {
		limits = append(limits, fmt.Sprintf("hostname=%s", config.LimitHostname))
	}
	if config.LimitFileExists != "" {
		limits = append(limits, fmt.Sprintf("fileexists=%s", config.LimitFileExists))
	}
	return strings.Join(limits, "; ")
}

// ProfileDelete - Delete one or more profiles from the server
type ProfileDelete struct {
	Positional struct {
		Profiles []string `description:"name of profile to delete" required:"1"`
	} `positional-args:"yes" required:"true"`
}

// Execute - Command
func (pd *ProfileDelete) Execute(args []string) (err error) {
	for _, p := range pd.Positional.Profiles {
		_, err := transport.RPC.DeleteImplantProfile(context.Background(), &clientpb.DeleteReq{
			Name: p,
		})
		if err != nil {
			err := log.Errorf("Failed to delete profile: %s\n", err)
			fmt.Printf(err.Error())
			continue
		} else {
			log.Infof("Deleted profile %s\n", p)
		}
	}
	return
}

func buildImplantName(name string) string {
	return strings.TrimSuffix(name, filepath.Ext(name))
}
