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

// RegistryCreateKey - Create a registry key .
type RegistryCreateKey struct {
	Positional struct {
		Key string `description:"registry key name" required:"1"`
	} `positional-args:"yes" required:"yes"`
	Options struct {
		Hive     string `long:"hive" short:"H" description:"registry hive" default:"HKCU"`
		Hostname string `long:"hostname" short:"o" description:"remove host to write values to"`
	} `group:"write options"`
}

// Execute - Create a registry key
func (rck *RegistryCreateKey) Execute(args []string) (err error) {

	hostname := rck.Options.Hostname
	hive := rck.Options.Hive

	regPath := rck.Positional.Key
	if strings.Contains(regPath, "/") {
		regPath = strings.ReplaceAll(regPath, "/", "\\")
	}
	slashIndex := strings.LastIndex(regPath, "\\")
	key := regPath[slashIndex+1:]
	regPath = regPath[:slashIndex]
	createKeyResp, err := transport.RPC.RegistryCreateKey(context.Background(), &sliverpb.RegistryCreateKeyReq{
		Hive:     hive,
		Path:     regPath,
		Key:      key,
		Hostname: hostname,
		Request:  core.ActiveTarget.Request(),
	})

	if err != nil {
		return log.Errorf("Error: %v", err)
	}

	if createKeyResp.Response != nil && createKeyResp.Response.Err != "" {
		return log.Errorf("Error: %s", createKeyResp.Response.Err)
	}
	log.Infof("Key created at %s\\%s", regPath, key)

	return
}
