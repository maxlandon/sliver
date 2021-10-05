package malleable

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

// Malleable - C2 Profiles management root command
type Malleable struct {
}

// Execute - C2 Profiles management root command
func (n *Malleable) Execute(args []string) (err error) {
	return
}

// Dialer - Create a new dialer C2 Profile for any available protocol
type Dialer struct {
}

// Execute - Create a new dialer C2 Profile for any available protocol
func (d *Dialer) Execute(args []string) (err error) {
	return
}

// Listener - Create a new listener C2 Profile for available protocol
type Listener struct{}

// Execute - Create a new listener C2 Profile for available protocol
func (l *Listener) Execute(args []string) (err error) {
	return
}
