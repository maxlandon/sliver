package websites

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
	"sort"

	"github.com/maxlandon/readline"

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/client/util"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
)

// WebsitesShow - Print the contents of a website.
type WebsitesShow struct {
	Args struct {
		Name string `description:"website name"`
	} `positional-args:"yes" required:"yes"`
}

// Execute - Print the contents of a website.
func (w *WebsitesShow) Execute(args []string) (err error) {
	err = listWebsiteContent(w, transport.RPC)
	return
}

func listWebsiteContent(w *WebsitesShow, rpc rpcpb.SliverRPCClient) (err error) {
	if w.Args.Name == "" {
		return
	}
	website, err := rpc.Website(context.Background(), &clientpb.Website{
		Name: w.Args.Name,
	})
	if err != nil {
		return log.Errorf("Failed to list website content %s", err)
	}
	if 0 < len(website.Contents) {
		displayWebsite(website)
	} else {
		log.Infof("No content for '%s'", w.Args.Name)
	}

	return
}

func displayWebsite(web *clientpb.Website) {

	table := util.NewTable(readline.Bold(readline.Yellow(web.Name)))
	headers := []string{"Path", "Content-Type", "Size"}
	headLen := []int{0, 10, 0}
	table.SetColumns(headers, headLen)

	sortedContents := []*clientpb.WebContent{}
	for _, content := range web.Contents {
		sortedContents = append(sortedContents, content)
	}
	sort.SliceStable(sortedContents, func(i, j int) bool {
		return sortedContents[i].Path < sortedContents[j].Path
	})

	for _, content := range sortedContents {
		size := readline.Dim(fmt.Sprintf("%d", content.Size))
		path := readline.Bold(content.Path)
		table.AppendRow([]string{path, content.ContentType, size})
	}
	table.Output()
}
