//go:build !windows

package handlers

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
	"os"

	"google.golang.org/protobuf/proto"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

var specialHandlers = map[uint32]TransportHandler{
	sliverpb.MsgKillSessionReq: killHandler,
}

// GetSpecialHandlers returns the specialHandlers map
func GetSpecialHandlers() map[uint32]TransportHandler {
	return specialHandlers
}

// c2 - A small interface allowing us to control
// the transports stack when killing the implant.
type c2 interface {
	Shutdown() error
}

func killHandler(data []byte, transports c2) error {
	killReq := &sliverpb.KillSessionReq{}
	err := proto.Unmarshal(data, killReq)
	// {{if .Config.Debug}}
	println("KILL called")
	// {{end}}
	if err != nil {
		return err
	}

	// Shutdown the complete transport stack
	if transports != nil {
		err = transports.Shutdown()
		if err != nil {
			print("Error shuting down transports: %s", err)
		}
	}

	// {{if .Config.Debug}}
	println("Let's exit!")
	// {{end}}
	os.Exit(0)
	return nil
}
