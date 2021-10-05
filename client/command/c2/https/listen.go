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
	"context"
	"io/ioutil"

	"github.com/bishopfox/sliver/client/command/c2"
	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

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

	// Declare profile
	profile := c2.ParseActionProfile(
		sliverpb.C2Channel_HTTPS,     // A Channel using Mutual TLS
		l.Args.LocalAddr,             // Targeting the host:[port] argument of our command
		sliverpb.C2Direction_Reverse, // A listener
	)
	profile.Persistent = l.BaseListenerOptions.Core.Persistent

	if profile.Port == 0 {
		profile.Port = 443
	}

	// HTTPS-specific options
	profile.Domains = []string{l.HTTPListenerOptions.Options.Domain} // Restrict responses to this domain
	profile.Website = l.HTTPListenerOptions.Options.Website
	profile.LetsEncrypt = l.HTTPListenerOptions.Options.LetsEncrypt

	log.Infof("Starting HTTPS %s:%d listener ...", profile.Domains[0], profile.Port)
	res, err := transport.RPC.StartHandlerStage(context.Background(), &clientpb.HandlerStageReq{
		Profile: profile,
		Request: core.ActiveTarget.Request(),
	})
	if err != nil {
		return log.Error(err)
	}
	if !res.Success {
		return log.Errorf("An unknown error happened: no success")
	}

	log.Infof("Successfully started HTTPS listener")
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
