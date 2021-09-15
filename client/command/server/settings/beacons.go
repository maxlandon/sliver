package settings

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
	"github.com/maxlandon/readline"

	"github.com/bishopfox/sliver/client/assets"
	"github.com/bishopfox/sliver/client/log"
)

// BeaconAutoResults - Automatically print the results from requests to beacons, or not.
type BeaconAutoResults struct {
	Positional struct {
		Setting string `description:"set to true to skip IsUserAnAdult confirmation on non-opsec functions" required:"1-1"`
	} `positional-args:"yes" required:"yes"`
}

// Execute - Automatically print the results from requests to beacons, or not.
func (a *BeaconAutoResults) Execute(args []string) (err error) {
	switch a.Positional.Setting {
	case "true":
		assets.UserClientSettings.BeaconAutoResults = true
		log.Infof("BeaconAutoResults mode set to %strue%s\n", readline.YELLOW, readline.RESET)
	case "false":
		assets.UserClientSettings.BeaconAutoResults = false
		log.Infof("BeaconAutoResults mode set to %sfalse%s\n", readline.YELLOW, readline.RESET)
	default:
		assets.UserClientSettings.BeaconAutoResults = true
		log.Warnf("Invalid argument (must be true/false): BeaconAutoResults defaulting to %strue%s\n", readline.YELLOW, readline.RESET)
	}
	return
}
