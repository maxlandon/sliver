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
	"errors"
	"path"
	"strings"

	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

var (
	// ErrInvalidFileType - Invalid file type
	ErrInvalidFileType = errors.New("invalid file type")
	// ErrInvalidLootType - Invalid loot type
	ErrInvalidLootType = errors.New("invalid loot type")
	// ErrNoLootFileData - No loot file data
	ErrNoLootFileData = errors.New("no loot file data")
)

// AddLootFile - Add a file as loot
func AddLootFile(name string, fileName string, data []byte, isCredential bool) error {
	if len(data) < 1 {
		return ErrNoLootFileData
	}
	var lootType clientpb.LootType
	if isCredential {
		lootType = clientpb.LootType_LOOT_CREDENTIAL
	} else {
		lootType = clientpb.LootType_LOOT_FILE
	}
	var lootFileType clientpb.FileType
	if isText(data) || strings.HasSuffix(fileName, ".txt") {
		lootFileType = clientpb.FileType_TEXT
	} else {
		lootFileType = clientpb.FileType_BINARY
	}
	loot := &clientpb.Loot{
		Name:     name,
		Type:     lootType,
		FileType: lootFileType,
		File: &commonpb.File{
			Name: path.Base(fileName),
			Data: data,
		},
	}
	if lootType == clientpb.LootType_LOOT_CREDENTIAL {
		loot.CredentialType = clientpb.CredentialType_FILE
	}
	_, err := transport.RPC.LootAdd(context.Background(), loot)
	return err
}

// AddLootUserPassword - Add user/password as loot
func AddLootUserPassword(name string, user string, password string) error {
	loot := &clientpb.Loot{
		Name:           name,
		Type:           clientpb.LootType_LOOT_CREDENTIAL,
		CredentialType: clientpb.CredentialType_USER_PASSWORD,
		Credential: &clientpb.Credential{
			User:     user,
			Password: password,
		},
	}
	_, err := transport.RPC.LootAdd(context.Background(), loot)
	return err
}

// AddLootAPIKey - Add a api key as loot
func AddLootAPIKey(name string, apiKey string) error {
	loot := &clientpb.Loot{
		Name:           name,
		Type:           clientpb.LootType_LOOT_CREDENTIAL,
		CredentialType: clientpb.CredentialType_API_KEY,
		Credential: &clientpb.Credential{
			APIKey: apiKey,
		},
	}
	_, err := transport.RPC.LootAdd(context.Background(), loot)
	return err
}
