package completion

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

import "github.com/maxlandon/readline"

// UserAtHostSSH - Display one of more groups of user @ host elements, with creds
// description when their type is compatible with SSH, for instance:
// user word:
// - current session user & detected users if any
// - users that have valid SSH key credentials, along with short key
// host:
// - current host, or detected one if any
func UserAtHostSSH(last string) (prefix string, comps []*readline.CompletionGroup) {

	// Users

	// Creds matching user
	return
}
