package reaction

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
	"os"

	"gopkg.in/AlecAivazis/survey.v1"

	"github.com/bishopfox/sliver/client/log"
)

// Reload - Reload reactions from disk, replaces the running configuration
type Reload struct{}

// Execute - Reload reactions from disk, replaces the running configuration
func (r *Reload) Execute(args []string) (err error) {

	if _, err := os.Stat(GetReactionFilePath()); os.IsNotExist(err) {
		return log.Errorf("Missing reaction file %s", GetReactionFilePath())
	}
	confirm := false
	prompt := &survey.Confirm{Message: "Reload reactions from disk?"}
	survey.AskOne(prompt, &confirm, nil)
	if !confirm {
		return
	}

	n, err := LoadReactions()
	if err != nil {
		log.Errorf("Failed to load reactions: %s", err)
	}
	log.Infof("Reloaded %d reactions from disk", n)

	return
}
