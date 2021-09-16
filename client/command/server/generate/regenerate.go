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
	"io/ioutil"
	"os"

	"github.com/bishopfox/sliver/client/constants"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
)

// Regenerate - Recompile an implant by name, passed as argument (completed)
type Regenerate struct {
	Positional struct {
		ImplantName string `description:"Name of Sliver implant to recompile" required:"1-1"`
	} `positional-args:"yes" required:"yes"`
	Options struct {
		Save string `long:"save" short:"s" description:"directory/file where to save binary"`
	} `group:"profile options"`
}

// Execute - Recompile an implant with a given profile
func (r *Regenerate) Execute(args []string) (err error) {
	if r.Positional.ImplantName == "" {
		return log.Errorf("Invalid implant name, see `help %s`\n", constants.RegenerateStr)
	}
	save := r.Options.Save
	if save == "" {
		save, _ = os.Getwd()
	}

	regenerate, err := transport.RPC.Regenerate(context.Background(), &clientpb.RegenerateReq{
		ImplantName: r.Positional.ImplantName,
	})
	if err != nil {
		return log.Errorf("Failed to regenerate implant %s", err)
	}
	if regenerate.File == nil {
		return log.Errorf("Failed to regenerate implant (no data)")
	}
	saveTo, err := saveLocation(save, regenerate.File.Name)
	if err != nil {
		return log.Error(err)
	}
	err = ioutil.WriteFile(saveTo, regenerate.File.Data, 0500)
	if err != nil {
		return log.Errorf("Failed to write to %s", err)
	}

	log.Infof("Implant binary saved to: %s\n", saveTo)
	return
}
