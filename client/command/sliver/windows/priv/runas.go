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
	"strings"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// RunAs - Run a new process in the context of the designated user (Windows Only)
type RunAs struct {
	Positional struct {
		Args []string `description:"(optional) arguments to pass to --process when executing"`
	} `positional-args:"yes"`

	Options struct {
		Username   string `long:"username" short:"u" description:"user to impersonate" default:"NT AUTHORITY\\SYSTEM"`
		RemotePath string `long:"process" short:"p" description:"process to start" required:"yes"`
	} `group:"run-as options"`
}

// Execute - Run a new process in the context of the designated user (Windows Only)
func (ra *RunAs) Execute(args []string) (err error) {

	username := ra.Options.Username
	process := ra.Options.RemotePath
	arguments := strings.Join(ra.Positional.Args, " ")

	runAsResp, err := transport.RPC.RunAs(context.Background(), &sliverpb.RunAsReq{
		Request:     core.ActiveTarget.Request(),
		Username:    username,
		ProcessName: process,
		Args:        arguments,
	})

	if err != nil {
		log.Errorf("Error: %v\n", err)
		return
	}

	if runAsResp.GetResponse().GetErr() != "" {
		log.Errorf("Error: %s\n", runAsResp.GetResponse().GetErr())
		return
	}

	log.Infof("Sucessfully ran %s %s on %s\n", process, arguments, core.ActiveTarget.Session.GetName())

	return
}
