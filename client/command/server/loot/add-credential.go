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

	"github.com/AlecAivazis/survey/v2"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
)

// AddCredentials - Add credentials to the server's loot store
type AddCredentials struct {
	Options struct {
		Name string `long:"name" short:"n" description:"Name for this loot credential"`
	} `group:"credential loot options"`
}

// Execute - Add credentials to the server's loot store
func (l *AddCredentials) Execute(args []string) (err error) {
	prompt := &survey.Select{
		Message: "Choose a credential type:",
		Options: []string{
			clientpb.CredentialType_API_KEY.String(),
			clientpb.CredentialType_USER_PASSWORD.String(),
		},
	}
	credType := ""
	survey.AskOne(prompt, &credType, survey.WithValidator(survey.Required))
	name := l.Options.Name
	if name == "" {
		namePrompt := &survey.Input{Message: "Credential Name: "}
		survey.AskOne(namePrompt, &name)
	}

	loot := &clientpb.Loot{
		Type:       clientpb.LootType_LOOT_CREDENTIAL,
		Name:       name,
		Credential: &clientpb.Credential{},
	}

	switch credType {
	case clientpb.CredentialType_USER_PASSWORD.String():
		loot.CredentialType = clientpb.CredentialType_USER_PASSWORD
		usernamePrompt := &survey.Input{Message: "Username: "}
		survey.AskOne(usernamePrompt, &loot.Credential.User)
		passwordPrompt := &survey.Input{Message: "Password: "}
		survey.AskOne(passwordPrompt, &loot.Credential.Password)
	case clientpb.CredentialType_API_KEY.String():
		loot.CredentialType = clientpb.CredentialType_API_KEY
		usernamePrompt := &survey.Input{Message: "API Key: "}
		survey.AskOne(usernamePrompt, &loot.Credential.APIKey)
	}

	loot, err = transport.RPC.LootAdd(context.Background(), loot)
	if err != nil {
		return log.Errorf("Failed to add credential: %s", err)
	}

	fmt.Println()
	log.Infof("Successfully added credential to server (%s)", loot.LootID)
	return
}
