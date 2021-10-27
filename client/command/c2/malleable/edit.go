package malleable

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
	"encoding/json"
	"fmt"

	"github.com/bishopfox/sliver/client/assets"
	"github.com/bishopfox/sliver/client/command/c2"
	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// Edit - Edit a Malleable C2 profile in your editor, with JSON Schema completion
// validation and documentation by default, if your editor supports it.
type Edit struct {
	Args struct {
		ProfileID string `description:"ID of profile to edit" required:"1-1"`
	} `positional-args:"yes" required:"yes"`
}

// Execute - Edit a Malleable C2 profile in your editor, with JSON Schema completion
func (e *Edit) Execute(args []string) (err error) {

	// Fetch all profiles from the server
	profiles, err := transport.RPC.GetMalleables(context.Background(), &clientpb.GetMalleablesReq{})
	if err != nil {
		return log.Error(err)
	}

	// Get the target profile among them.
	var prof *sliverpb.Malleable
	for _, p := range profiles.Profiles {
		if c2.GetShortID(p.ID) == e.Args.ProfileID {
			prof = p
		}
	}

	// Always ensure the JSON schema path is set
	prof.Schema = assets.GetMalleableSchemaPath()

	// And marshal the profile as JSON indented bytes, before
	// passing it to the console system editor function.
	profileBuffer, err := json.MarshalIndent(prof, "", "\t")
	if err != nil {
		return log.Errorf("Failed to marshal Profile buffer as JSON for editing: %s", err)
	}

	// Start the editor with the profile buffer, and block until
	// the user quits the editor command. This returns an updated
	// version of the Profile buffer, is a different one has been saved.
	updatedBuffer, err := core.Console.SystemEditor(profileBuffer, assets.SliverMalleableSchema)
	if err != nil {
		return log.Errorf("Error returning from Editor: %s", err)
	}

	// Unmarshal this updated buffer into the profile type
	err = json.Unmarshal(updatedBuffer, prof)
	if err != nil {
		return log.Errorf("Failed to unmarshal edited Profile into its type: %s")
	}

	fmt.Println(prof)

	return
}
