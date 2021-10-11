package filesystem

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
	"path/filepath"

	"github.com/maxlandon/readline"
	"google.golang.org/protobuf/proto"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/client/util"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// ListDirectories - List directory contents
type ListDirectories struct {
	Positional struct {
		Path []string `description:"session directory/file"`
	} `positional-args:"yes"`
}

// Execute - List directory contents
func (ls *ListDirectories) Execute(args []string) (err error) {
	if err := core.ActiveTarget.Unavailable(); err != nil {
		return err
	}
	_, beacon := core.ActiveTarget.Targets()

	if len(ls.Positional.Path) == 0 {
		ls.Positional.Path = []string{"."}
	}

	for _, path := range ls.Positional.Path {
		// Formatting
		if (path == "~" || path == "~/") && core.ActiveTarget.OS() == "linux" {
			path = filepath.Join("/home", core.ActiveTarget.Username())
		}
		// Make request
		resp, err := transport.RPC.Ls(context.Background(), &sliverpb.LsReq{
			Path:    path,
			Request: core.ActiveTarget.Request(),
		})
		if err != nil {
			log.PrintErrorf(err.Error())
			continue
		}

		// Beacon
		if beacon != nil {
			ls.executeAsync(resp)
			continue
		}

		// Session
		ls.executeSync(resp)
	}
	return
}

// ListDirectories - List directory contents (asynchronous/beacon)
func (ls *ListDirectories) executeAsync(resp *sliverpb.Ls) (err error) {

	if resp.Response != nil && resp.Response.Async {
		core.AddBeaconCallback(resp.Response.TaskID, func(task *clientpb.BeaconTask) {
			err := proto.Unmarshal(task.Response, resp)
			if err != nil {
				log.ErrorfAsync("Failed to decode response: %s", err)
				return
			}
			log.PrintfAsync(printDirList(resp))
		})
	}
	return nil
}

// ListDirectories - List directory contents (synchronous/session)
func (ls *ListDirectories) executeSync(resp *sliverpb.Ls) (err error) {
	fmt.Printf(printDirList(resp))
	return
}

func printDirList(dirList *sliverpb.Ls) string {
	title := fmt.Sprintf("%s%s%s%s", readline.BOLD, readline.BLUE, dirList.Path, readline.RESET)

	table := util.NewTable(title)
	headers := []string{"Name", "Size"}
	headLen := []int{0, 0}
	table.SetColumns(headers, headLen)

	for _, fileInfo := range dirList.Files {
		var row []string
		if fileInfo.IsDir {
			row = []string{readline.Blue(fileInfo.Name), ""}
		} else {
			row = []string{fileInfo.Name, util.ByteCountBinary(fileInfo.Size)}
		}
		table.AppendRow(row)
	}
	return table.Output()
}
