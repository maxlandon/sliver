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

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/client/util"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// ListSessionDirectories - List directory contents
type ListSessionDirectories struct {
	Positional struct {
		Path []string `description:"session directory/file"`
	} `positional-args:"yes"`
}

// Execute - Command
func (ls *ListSessionDirectories) Execute(args []string) error {

	if len(ls.Positional.Path) == 0 {
		ls.Positional.Path = []string{"."}
	}

	// Other paths/files
	for _, path := range ls.Positional.Path {
		if (path == "~" || path == "~/") && core.ActiveTarget.Session.OS == "linux" {
			path = filepath.Join("/home", core.ActiveTarget.Session.Username)
		}
		resp, err := transport.RPC.Ls(context.Background(), &sliverpb.LsReq{
			Path:    path,
			Request: core.ActiveTarget.Request(),
		})
		if err != nil {
			log.Errorf("%s\n", err)
		} else {
			printDirList(resp)
		}
	}

	return nil
}

func printDirList(dirList *sliverpb.Ls) {
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
	table.Output()
	fmt.Println()
}
