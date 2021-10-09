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
	"fmt"
	"os"
	"time"

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

var (
	minBeaconInterval         = 15 * time.Second
	ErrBeaconIntervalTooShort = fmt.Errorf("Beacon interval must be %v or greater", minBeaconInterval)
)

// GenerateBeacon - Generate a beacon implant binary
type GenerateBeacon struct {
	// Classic Session options
	StageOptions // This commands works the same as generate, and needs full options.

	// Beacon options
	BeaconOptions struct {
		Days    int64 `long:"days" short:"D" description:"beacon interval days" default:"0"`
		Hours   int64 `long:"hours" short:"H" description:"beacon interval hours" default:"0"`
		Minutes int64 `long:"minutes" short:"M" description:"beacon interval minutes" default:"15"`
		Seconds int64 `long:"seconds" short:"S" description:"beacon interval seconds" default:"0"`
		Jitter  int64 `long:"jitter" short:"J" description:"beacon interval jitter in seconds" default:"30"`
	} `group:"beacon options"`
}

// Execute - Generate a beacon implant binary
func (g *GenerateBeacon) Execute(args []string) (err error) {

	config, err := ParseCompileFlags(g.StageOptions)
	if err != nil {
		return log.Error(err)
	}
	if config == nil {
		return log.Errorf("An unknown error happened when parsing Stage options: no configuration returned")
	}

	// Adapt C2 profiles for beacon type, only
	// if they don't have an ID: if they have
	// that means the profile was fetched from
	// the server and it might be an additional
	// session transport included in the build.
	for _, transport := range config.C2S {
		if transport.ID == "" {
			transport.Type = sliverpb.C2Type_Beacon
		}
	}

	save := g.CoreOptions.Save
	if save == "" {
		save, _ = os.Getwd()
	}
	_, err = Compile(config, save)
	return
}
