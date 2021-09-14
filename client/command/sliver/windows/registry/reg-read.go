package registry

/*
	sliver implant framework
	copyright (c) 2019  bishop fox

	this program is free software: you can redistribute it and/or modify
	it under the terms of the gnu general public license as published by
	the free software foundation, either version 3 of the license, or
	(at your option) any later version.

	this program is distributed in the hope that it will be useful,
	but without any warranty; without even the implied warranty of
	merchantability or fitness for a particular purpose.  see the
	gnu general public license for more details.

	you should have received a copy of the gnu general public license
	along with this program.  if not, see <https://www.gnu.org/licenses/>.
*/

import (
	"context"
	"strings"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// RegistryRead - Read values from the Windows registry.
type RegistryRead struct {
	Positional struct {
		KeyPath string `description:"path to registry key" required:"1"`
	} `positional-args:"yes" required:"yes"`
	Options struct {
		Hive     string `long:"hive" short:"H" description:"registry hive" default:"HKCU"`
		Hostname string `long:"hostname" short:"o" description:"remove host to read values from"`
	} `group:"read options"`
}

// Execute - Read values from the Windows registry.
func (rr *RegistryRead) Execute(args []string) (err error) {

	hostname := rr.Options.Hostname
	hive := rr.Options.Hive

	regPath := rr.Positional.KeyPath
	if strings.Contains(regPath, "/") {
		regPath = strings.ReplaceAll(regPath, "/", "\\")
	}
	slashIndex := strings.LastIndex(regPath, "\\")
	key := regPath[slashIndex+1:]
	regPath = regPath[:slashIndex]
	regRead, err := transport.RPC.RegistryRead(context.Background(), &sliverpb.RegistryReadReq{
		Hive:     hive,
		Path:     regPath,
		Key:      key,
		Hostname: hostname,
		Request:  core.ActiveTarget.Request(),
	})

	if err != nil {
		return log.Errorf("Error: %v", err)
	}

	if regRead.Response != nil && regRead.Response.Err != "" {
		return log.Errorf("Error: %s", regRead.Response.Err)
	}
	log.Infof(regRead.Value)

	return
}
