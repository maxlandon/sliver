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
	"io/ioutil"

	"github.com/bishopfox/sliver/client/command/c2"
)

// ListenerOptions - All listener options needed by HTTP handlers
type ListenerOptions struct {
	Options struct {
		Domain      string `long:"domain" short:"d" description:"limit responses to specific domain)"`
		LetsEncrypt bool   `long:"lets-encrypt" short:"e" description:"attempt to provision a let's encrypt certificate"`
		Website     string `long:"website" short:"w" description:"website name (see 'websites' command)"`
	} `group:"HTTP(S) listener options"`
}

// Listen - Start an HTTPS listener on the server
type Listen struct {
	Args struct {
		LocalAddr string `description:"interface:[port] to bind the HTTP(S) server to"`
	} `positional-args:"yes"`

	BaseListenerOptions c2.ListenerOptions
	HTTPListenerOptions ListenerOptions
	c2.SecurityOptions
}

// Execute - Start an HTTPS listener on the server
func (l *Listen) Execute(args []string) (err error) {
	return
}

func getLocalCertificatePair(certPath, keyPath string) ([]byte, []byte, error) {
	if certPath == "" && keyPath == "" {
		return nil, nil, nil
	}
	cert, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

// Serve - Serve an implant stage with an HTTP server
type Serve struct {
	Args struct {
		Profile   string `description:"implant profile/build to serve a stage" required:"1-1"`
		LocalAddr string `description:"interface:[port] to bind the HTTP(S) server to" required:"1-1"`
	} `positional-args:"yes" required:"yes"`

	BaseListenerOptions c2.ListenerOptions
	HTTPListenerOptions ListenerOptions
	c2.SecurityOptions
}

// Execute - Serve an implant stage with an HTTP server
func (s *Serve) Execute(args []string) (err error) {
	return
}
