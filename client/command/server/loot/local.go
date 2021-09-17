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
	"io/ioutil"
	"os"
	"path"

	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// Local - Add a local file to the server's loot store
type Local struct {
	Positional struct {
		LocalPath string `description:"path to local file to add as loot" required:"1-1"`
	} `positional-args:"true" required:"true"`
	Options struct {
		Name     string `long:"name" short:"n" description:"Name of this piece of loot"`
		Type     string `long:"type" short:"t" description:"force a specific loot type (file/cred)"`
		FileType string `long:"file-type" short:"f" description:"force a specific file type (binary/text)"`
	} `group:"local loot options"`
}

// Execute - Add a local file to the server's loot store
func (l *Local) Execute(args []string) (err error) {
	localPath := l.Positional.LocalPath
	if _, err := os.Stat(localPath); os.IsNotExist(err) {
		return log.Errorf("Path '%s' not found", localPath)
	}

	name := l.Options.Name
	if name == "" {
		name = path.Base(localPath)
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

	lootFileTypeStr := l.Options.FileType
	var lootFileType clientpb.FileType
	if lootFileTypeStr != "" {
		lootFileType, err = lootFileTypeFromHumanStr(lootFileTypeStr)
		if err != nil {
			return log.Errorf("Invalid loot file type: %s", err)
		}
	} else {
		if isTextFile(localPath) {
			lootFileType = clientpb.FileType_TEXT
		} else {
			lootFileType = clientpb.FileType_BINARY
		}
	}
	data, err := ioutil.ReadFile(localPath)
	if err != nil {
		return log.Errorf("Failed to read file: %s", err)
	}

	loot := &clientpb.Loot{
		Name:     name,
		Type:     lootType,
		FileType: lootFileType,
		File: &commonpb.File{
			Name: path.Base(localPath),
			Data: data,
		},
	}
	if lootType == clientpb.LootType_LOOT_CREDENTIAL {
		loot.CredentialType = clientpb.CredentialType_FILE
	}

	ctrl := make(chan bool)
	log.SpinUntil(fmt.Sprintf("Uploading loot from %s", localPath), ctrl)
	loot, err = transport.RPC.LootAdd(context.Background(), loot)
	ctrl <- true
	<-ctrl
	if err != nil {
		return log.Errorf("Uploading error: %s", err)
	}

	log.Infof("Successfully added loot to server: %s (%s) [%s]", loot.Name, loot.LootID, loot.Type.String())
	return
}
