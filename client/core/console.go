package core

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

import "github.com/maxlandon/gonsole"

var (
	// Console - At startup the console has passed itself to this package, so that
	// we can question the application parser for timeout/request options.
	Console = gonsole.NewConsole()
)

var (
	// ClientID - Given by the server when requiring the console configuration.
	// Whether or not there is one, this clientID is written, and should stay the same
	// for the whole lifetime of the console.
	ClientID string
)

// GetCommandForMenu - Allows different menus to access each other command.
func GetCommandForMenu(commandName string, menu string) *gonsole.Command {
	m := Console.GetMenu(menu)
	for _, c := range m.Commands() {
		if c.Name == commandName {
			return c
		}
	}
	return nil
}
