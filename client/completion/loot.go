package completion

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

	"github.com/maxlandon/readline"

	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// LootIDs - Complete all IDs of all loots, structured in groups related to their types.
// Further, some types are ordered by subtype, like for the various credentials supported.
func LootIDs() (comps []*readline.CompletionGroup) {

	allLoot, err := transport.RPC.LootAll(context.Background(), &commonpb.Empty{})
	if err != nil {
		return
	}

	// Files ---------------------------------------------------------------------------------
	filesComp := &readline.CompletionGroup{
		Name:         "files",
		Descriptions: map[string]string{},
		DisplayType:  readline.TabDisplayList,
	}

	for _, loot := range allLoot.Loot {
		if loot.Type == clientpb.LootType_LOOT_FILE {

			var shortID string
			if len(shortID) < 8 {
				shortID = shortID[:len(loot.LootID)]
			} else {
				shortID = loot.LootID[:8]
			}
			filesComp.Suggestions = append(filesComp.Suggestions, shortID)

			var fileType string
			if loot.FileType.String() == "" {
				fileType = "unknown"
			} else {
				fileType = loot.FileType.String()
			}
			var name string
			if loot.File != nil {
				name = loot.File.Name
			} else {
				name = "no name"
			}
			desc := fmt.Sprintf("%s - (%s)", name, fileType)
			filesComp.Descriptions[shortID] = readline.DIM + desc + readline.RESET
		}
	}
	comps = append(comps, filesComp)

	// Credentials ----------------------------------------------------------------------------
	credsComp := &readline.CompletionGroup{
		Name:         "credentials",
		Descriptions: map[string]string{},
		DisplayType:  readline.TabDisplayList,
	}

	// Make ordered lists of all types, we'll add them after in the correct order
	userPass := []string{}
	userPassDesc := map[string]string{}
	apiKeys := []string{}
	apiKeyDesc := map[string]string{}
	files := []string{}
	filesDesc := map[string]string{}
	other := []string{}
	otherDesc := map[string]string{}

	// For each loot
	for _, loot := range allLoot.Loot {

		// Compute a shortened ID
		var shortID string
		if len(loot.LootID) < 8 {
			shortID = loot.LootID[:len(loot.LootID)]
		} else {
			shortID = loot.LootID[:8]
		}

		// And if a credential, process it
		if loot.Type == clientpb.LootType_LOOT_CREDENTIAL {
			// Add user-password first
			if loot.CredentialType == clientpb.CredentialType_USER_PASSWORD {
				userPass = append(userPass, shortID)
				desc := fmt.Sprintf("(user:pass) %s : %s", loot.Credential.User, loot.Credential.Password)
				userPassDesc[shortID] = readline.DIM + desc + readline.RESET
			}

			// Then API Keys
			if loot.CredentialType == clientpb.CredentialType_API_KEY {
				apiKeys = append(apiKeys, shortID)
				desc := fmt.Sprintf("(API key) %s", loot.Credential.APIKey)
				apiKeyDesc[shortID] = readline.DIM + desc + readline.RESET
			}

			// Then files
			if loot.CredentialType == clientpb.CredentialType_FILE {
				files = append(files, shortID)
				var fileType string
				if loot.FileType.String() == "" {
					fileType = "unknown"
				} else {
					fileType = loot.FileType.String()
				}
				var name string
				if loot.File != nil {
					name = loot.File.Name
				} else {
					name = "no name"
				}
				desc := fmt.Sprintf("(file) (%s) [%s]", name, fileType)
				filesDesc[shortID] = readline.DIM + desc + readline.RESET
			}

			// Then others
			if loot.CredentialType == clientpb.CredentialType_NO_CREDENTIAL {
				other = append(other, shortID)
				desc := fmt.Sprintf("(other) %s - (%s)", loot.Credential.User, loot.Credential.Password)
				otherDesc[shortID] = readline.DIM + desc + readline.RESET
			}

		}
	}
	// Add in correct order
	credsComp.Suggestions = append(credsComp.Suggestions, userPass...)
	for k, v := range userPassDesc {
		credsComp.Descriptions[k] = v
	}
	credsComp.Suggestions = append(credsComp.Suggestions, apiKeys...)
	for k, v := range apiKeyDesc {
		credsComp.Descriptions[k] = v
	}
	credsComp.Suggestions = append(credsComp.Suggestions, files...)
	for k, v := range filesDesc {
		credsComp.Descriptions[k] = v
	}
	credsComp.Suggestions = append(credsComp.Suggestions, other...)
	for k, v := range otherDesc {
		credsComp.Descriptions[k] = v
	}
	// And add the whole credentials group
	comps = append(comps, credsComp)

	return comps
}
