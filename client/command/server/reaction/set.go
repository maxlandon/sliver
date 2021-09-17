package reaction

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
	"errors"
	"fmt"
	"strings"

	"gopkg.in/AlecAivazis/survey.v1"

	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
)

var (
	// ErrNonReactableEvent - Event does not exist or is not supported by reactions
	ErrNonReactableEvent = errors.New("non-reactable event type")
)

// Set - Set a reaction to an event
type Set struct {
	Positional struct {
		Event string `description:"event type to set reaction for" required:"1-1"`
	} `positional-args:"yes" required:"yes"`
}

// Execute - Set a reaction to an event
func (r *Set) Execute(args []string) (err error) {
	eventType, err := getEventType(r.Positional.Event)
	if err != nil {
		return log.Error(err)
	}
	log.Infof("Setting reaction to: %s \n", EventTypeToTitle(eventType))
	rawCommands, err := userCommands()
	if err != nil {
		return log.Errorf("Failed to save commands: %s", err)
	}
	commands := []string{}
	for _, rawCommand := range strings.Split(rawCommands, "\n") {
		if rawCommand != "" {
			commands = append(commands, rawCommand)
		}
	}

	reaction := core.Reactions.Add(core.Reaction{
		EventType: eventType,
		Commands:  commands,
	})

	fmt.Println()
	log.Infof("Set reaction to %s (id: %d)", eventType, reaction.ID)
	return
}

func getEventType(rawEventType string) (string, error) {
	if rawEventType == "" {
		return selectEventType()
	}
	for _, eventType := range core.ReactableEvents {
		if eventType == rawEventType {
			return eventType, nil
		}
	}
	return "", ErrNonReactableEvent
}

func selectEventType() (string, error) {
	prompt := &survey.Select{
		Message: "Select an event:",
		Options: core.ReactableEvents,
	}
	selection := ""
	err := survey.AskOne(prompt, &selection, nil)
	if err != nil {
		return "", err
	}
	for _, eventType := range core.ReactableEvents {
		if eventType == selection {
			return eventType, nil
		}
	}
	return "", ErrNonReactableEvent
}

func userCommands() (string, error) {
	text := ""
	prompt := &survey.Multiline{
		Message: "Enter commands: ",
	}
	err := survey.AskOne(prompt, &text, nil)
	return text, err
}
