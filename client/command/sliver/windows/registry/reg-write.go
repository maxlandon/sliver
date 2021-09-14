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
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// RegistryWrite - Write values to the Windows registry.
type RegistryWrite struct {
	Positional struct {
		Key   string `description:"registry key name" required:"1"`
		Value string `description:"registry key value" required:"1"`
	} `positional-args:"yes" required:"yes"`
	Options struct {
		Hive     string `long:"hive" short:"H" description:"registry hive" default:"HKCU"`
		Hostname string `long:"hostname" short:"o" description:"remove host to write values to"`
		Type     string `long:"type" short:"T" description:"type of value to write (if binary, you must provide a path with --path)" default:"string"`
		Path     string `long:"path" short:"p" description:"path to the binary file to write"`
	} `group:"write options"`
}

// Execute - Write values to the Windows registry.
func (rw *RegistryWrite) Execute(args []string) (err error) {
	var (
		dwordValue  uint32
		qwordValue  uint64
		stringValue string
		binaryValue []byte
	)

	binPath := rw.Options.Path
	hostname := rw.Options.Hostname
	flagType := rw.Options.Type
	valType, err := getType(flagType)
	if err != nil {
		return log.Errorf("Error: %v", err)
	}
	hive := rw.Options.Hive

	regPath := rw.Positional.Key
	if strings.Contains(regPath, "/") {
		regPath = strings.ReplaceAll(regPath, "/", "\\")
	}
	slashIndex := strings.LastIndex(regPath, "\\")
	key := regPath[slashIndex+1:]
	regPath = regPath[:slashIndex]
	value := rw.Positional.Value
	switch valType {
	case sliverpb.RegistryTypeBinary:
		var (
			v   []byte
			err error
		)
		if binPath == "" {
			v, err = hex.DecodeString(value)
			if err != nil {
				return log.Errorf("Error: %v", err)
			}
		} else {
			v, err = ioutil.ReadFile(binPath)
			if err != nil {
				return log.Errorf("Error: %v", err)
			}
		}
		binaryValue = v
	case sliverpb.RegistryTypeDWORD:
		v, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return log.Errorf("Error: %v", err)
		}
		dwordValue = uint32(v)
	case sliverpb.RegistryTypeQWORD:
		v, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return log.Errorf("Error: %v", err)
		}
		qwordValue = v
	case sliverpb.RegistryTypeString:
		stringValue = value
	default:
		return log.Errorf("Invalid type")
	}
	regWrite, err := transport.RPC.RegistryWrite(context.Background(), &sliverpb.RegistryWriteReq{
		Request:     core.ActiveTarget.Request(),
		Hostname:    hostname,
		Hive:        hive,
		Path:        regPath,
		Type:        valType,
		Key:         key,
		StringValue: stringValue,
		DWordValue:  dwordValue,
		QWordValue:  qwordValue,
		ByteValue:   binaryValue,
	})

	if err != nil {
		return log.Errorf("Error: %v", err)
	}
	if regWrite.Response != nil && regWrite.Response.Err != "" {
		return log.Errorf("Error: %v", regWrite.Response.Err)
	}
	log.Infof("Value written to registry\n")

	return
}

func getType(t string) (uint32, error) {
	var res uint32
	switch t {
	case "binary":
		res = sliverpb.RegistryTypeBinary
	case "dword":
		res = sliverpb.RegistryTypeDWORD
	case "qword":
		res = sliverpb.RegistryTypeQWORD
	case "string":
		res = sliverpb.RegistryTypeString
	default:
		return res, fmt.Errorf("invalid type %s", t)
	}
	return res, nil
}
