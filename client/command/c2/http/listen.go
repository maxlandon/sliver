package http

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

import "github.com/bishopfox/sliver/client/command/c2"

// Listen - Start an HTTPS listener on the server
type Listen struct {
	Args struct {
		LocalAddr string `description:"interface:[port] to bind the HTTP server to"`
	} `positional-args:"yes"`

	BaseListenerOptions c2.ListenerOptions
	c2.SecurityOptions
}

// Execute - Start an HTTPS listener on the server
func (l *Listen) Execute(args []string) (err error) {
	return
}

// Serve - Serve an implant stage with an HTTP server
type Serve struct {
	Args struct {
		Profile   string `description:"implant profile/build to serve a stage"`
		LocalAddr string `description:"interface:[port] to bind the HTTP server to"`
	} `positional-args:"yes"`

	BaseListenerOptions c2.ListenerOptions
	c2.SecurityOptions
}

// Execute - Serve an implant stage with an HTTP server
func (s *Serve) Execute(args []string) (err error) {
	return
}
