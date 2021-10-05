package https

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
	"github.com/bishopfox/sliver/client/command/c2"
	"github.com/bishopfox/sliver/client/command/c2/http"
)

// ListenerOptions - All listener options needed by HTTP handlers
type ListenerOptions struct {
	Options struct {
		Domain      string `long:"domain" short:"d" description:"limit responses to specific domain)"`
		LetsEncrypt bool   `long:"lets-encrypt" short:"e" description:"attempt to provision a let's encrypt certificate"`
		Website     string `long:"website" short:"w" description:"website name (see 'websites' command)"`
	} `group:"HTTP(S) listener options"`
}

// Listener - Create a new HTTPS server listener C2 Profile
type Listener struct {
	Args struct {
		LocalAddr string `description:"host:port address to bind server to"`
	} `positional-args:"yes"`

	c2.ListenerOptions
	HTTPListenerOptions ListenerOptions
	c2.ProfileOptions
	c2.SecurityOptions

	// HTTP C2 Profile configurations
	http.AdvancedOptions
}

// Execute - Create a new HTTPS server listener C2 Profile
func (l *Listener) Execute(args []string) (err error) {

	return
}
