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
	"os"

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"

	"github.com/bishopfox/sliver/client/command/server/generate"
)

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
		implantFile, err := generate.Compile(profile.Config, save)
		if err != nil {
			return err
		}
		profile.Config.Name = generate.BuildImplantName(implantFile.Name)
		_, err = transport.RPC.SaveImplantProfile(context.Background(), profile)
		if err != nil {
			return log.Errorf("could not update implant profile: %v", err)
		}
	} else {
		return log.Errorf("No profile with name '%s'", name)
	}
	return
}
