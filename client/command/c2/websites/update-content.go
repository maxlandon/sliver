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

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
)

// WebsiteType - Update a path's content-type
type WebsiteType struct {
	WebsiteOptions `group:"content options"`
}

// Execute - Command
func (w *WebsiteType) Execute(args []string) (err error) {
	websiteName := w.WebsiteOptions.Website
	if websiteName == "" {
		return log.Errorf("Must specify a website name via --website, see --help")
	}
	webPath := w.WebsiteOptions.WebPath
	if webPath == "" {
		return log.Errorf("Must specify a web path via --web-path, see --help")
	}
	contentType := w.WebsiteOptions.ContentType
	if contentType == "" {
		return log.Errorf("Must specify a new --content-type, see --help")
	}

	updateWeb := &clientpb.WebsiteAddContent{
		Name:     websiteName,
		Contents: map[string]*clientpb.WebContent{},
	}
	updateWeb.Contents[webPath] = &clientpb.WebContent{
		ContentType: contentType,
	}

	web, err := transport.RPC.WebsiteUpdateContent(context.Background(), updateWeb)
	if err != nil {
		return log.Error(err)
	}
	displayWebsite(web)
	return
}
