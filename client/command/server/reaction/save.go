package reaction

import (
	"os"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"gopkg.in/AlecAivazis/survey.v1"
)

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

// Save - Save current reactions to disk
type Save struct{}

// Execute - Save the current reactions to disk
func (r *Save) Execute(args []string) (err error) {
	if _, err = os.Stat(GetReactionFilePath()); !os.IsNotExist(err) {
		confirm := false
		prompt := &survey.Confirm{Message: "Overwrite reactions on disk?"}
		survey.AskOne(prompt, &confirm, nil)
		if !confirm {
			return
		}
	}
	err = SaveReactions(core.Reactions.All())
	if err != nil {
		return log.Errorf("Failed to save reactions: %s", err)
	}
	log.Infof("Saved reactions to disk")
	return
}
