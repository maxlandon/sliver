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
	"gopkg.in/AlecAivazis/survey.v1"

	"github.com/bishopfox/sliver/client/assets"
	"github.com/bishopfox/sliver/client/log"
)

// AutoAdult - Set the AutoAdult parameter for this user
type AutoAdult struct {
	Positional struct {
		Setting string `description:"set to true to skip IsUserAnAdult confirmation on non-opsec functions" required:"1-1"`
	} `positional-args:"yes" required:"yes"`
}

// Execute - Set the AutoAdult parameter for this user
func (a *AutoAdult) Execute(args []string) (err error) {
	switch a.Positional.Setting {
	case "true":
		assets.UserClientSettings.AutoAdult = true
		log.Infof("AutoAdult mode set to %strue%s", readline.YELLOW, readline.RESET)
	case "false":
		assets.UserClientSettings.AutoAdult = false
		log.Infof("AutoAdult mode set to %sfalse%s", readline.YELLOW, readline.RESET)
	default:
		assets.UserClientSettings.AutoAdult = false
		log.Warnf("Invalid argument (must be true/false): AutoAdult defaulting to %sfalse%s", readline.YELLOW, readline.RESET)
	}
	return
}

// IsUserAnAdult - This should be called for any dangerous (OPSEC-wise) functions
func IsUserAnAdult() bool {
	confirm := false
	prompt := &survey.Confirm{Message: "This action is bad OPSEC, are you an adult?"}
	survey.AskOne(prompt, &confirm, nil)
	return confirm
}
