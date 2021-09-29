package transports

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

// Show - Show all or some C2 transports in detail for the current session or context
type Show struct {
	Args struct {
		TransportID []string `description:"(optional) one or more malleable C2 transports to show" required:"1"`
	} `positional-args:"yes"`
}

// Execute - Show all or some C2 transports
func (l *Show) Execute(args []string) (err error) {

	return
}
