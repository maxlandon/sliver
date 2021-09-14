package sessions

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
	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
)

// Background - Exit from implant context.
type Background struct{}

// Execute - Exit from implant context.
func (b *Background) Execute(args []string) (err error) {

	// Takes care of menu switching, unregistering session refreshing history, etc...
	core.UnsetActiveSession()
	log.Infof("Background ...\n")

	return
}
