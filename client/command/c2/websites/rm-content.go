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
	"strings"

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
)

// WebsitesDeleteContent - Remove content from a website
type WebsitesDeleteContent struct {
	WebsiteOptions `group:"content options"`
}

// Execute - Command
func (w *WebsitesDeleteContent) Execute(args []string) (err error) {
	name := w.Website
	webPath := w.WebPath
	recursive := w.Recursive

	if name == "" {
		return log.Errorf("Must specify a website name via --website, see --help")
	}
	if webPath == "" {
		return log.Errorf("Must specify a web path via --web-path, see --help")
	}

	website, err := transport.RPC.Website(context.Background(), &clientpb.Website{
		Name: name,
	})
	if err != nil {
		return log.Error(err)
	}

	rmWebContent := &clientpb.WebsiteRemoveContent{
		Name:  name,
		Paths: []string{},
	}
	if recursive {
		for contentPath := range website.Contents {
			if strings.HasPrefix(contentPath, webPath) {
				rmWebContent.Paths = append(rmWebContent.Paths, contentPath)
			}
		}
	} else {
		rmWebContent.Paths = append(rmWebContent.Paths, webPath)
	}
	web, err := transport.RPC.WebsiteRemoveContent(context.Background(), rmWebContent)
	if err != nil {
		return log.Errorf("Failed to remove content %s", err)
	}
	displayWebsite(web)
	return
}
