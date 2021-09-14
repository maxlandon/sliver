package proc

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
	"strings"

	"github.com/maxlandon/readline"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/client/util"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

const (
	normal = "\033[0m"
	red    = "\033[31m"
)

var (
	// Stylizes known processes in the `ps` command
	knownProcs = map[string]string{
		"ccSvcHst.exe":    red, // SEP
		"cb.exe":          red, // Carbon Black
		"MsMpEng.exe":     red, // Windows Defender
		"smartscreen.exe": red, // Windows Defender Smart Screen
	}
)

// PS - List session host processes.
type PS struct {
	Options struct {
		PID   int32  `long:"pid" short:"p" description:"process ID" default:"-1"`
		Exe   string `long:"exe" short:"e" description:"string pattern in executable name"`
		Owner string `long:"owner" short:"o" description:"user-owned processes"`
	} `group:"process filters"`
}

// Execute - List session host processes.
func (p *PS) Execute(args []string) (err error) {

	pidFilter := p.Options.PID
	exeFilter := p.Options.Exe
	ownerFilter := p.Options.Owner

	ps, err := transport.RPC.Ps(context.Background(), &sliverpb.PsReq{
		Request: core.ActiveTarget.Request(),
	})
	if err != nil {
		return log.Errorf("%s", err)
	}

	table := util.NewTable("")
	headers := []string{"PID", "PPID", "Executable", "owner"}
	headLen := []int{0, 0, 10, 0}
	table.SetColumns(headers, headLen)

	for _, proc := range ps.Processes {
		var lineColor = ""

		if pidFilter != -1 && proc.Pid == pidFilter {
			lineColor = printProcInfo(proc, core.ActiveTarget.Session)
		}
		if exeFilter != "" && strings.HasPrefix(proc.Executable, exeFilter) {
			lineColor = printProcInfo(proc, core.ActiveTarget.Session)
		}
		if ownerFilter != "" && strings.HasPrefix(proc.Owner, ownerFilter) {
			lineColor = printProcInfo(proc, core.ActiveTarget.Session)
		}
		if pidFilter == -1 && exeFilter == "" && ownerFilter == "" {
			lineColor = printProcInfo(proc, core.ActiveTarget.Session)
		}

		pid := fmt.Sprintf("%s%d%s", lineColor, proc.Pid, readline.RESET)
		ppid := fmt.Sprintf("%s%d%s", lineColor, proc.Ppid, readline.RESET)
		exe := fmt.Sprintf("%s%s%s", lineColor, proc.Executable, readline.RESET)
		owner := fmt.Sprintf("%s%s%s", lineColor, proc.Owner, readline.RESET)

		table.AppendRow([]string{pid, ppid, exe, owner})
	}
	table.Output()

	return
}

// printProcInfo - Stylizes the process information
func printProcInfo(proc *commonpb.Process, session *clientpb.Session) string {
	color := normal
	if modifyColor, ok := knownProcs[proc.Executable]; ok {
		color = modifyColor
	}
	if session != nil && proc.Pid == session.PID {
		color = readline.GREEN
	}
	return color
}
