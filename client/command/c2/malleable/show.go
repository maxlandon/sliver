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
	"fmt"

	"github.com/bishopfox/sliver/client/command/c2"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
)

// Show - Show one or more C2 profiles in detailed output
type Show struct {
	Args struct {
		ProfileID []string `description:"one or more malleable C2 profiles to show" required:"1"`
	} `positional-args:"yes" required:"yes"`
}

// Execute - Show one or more C2 profiles in detailed output
func (s *Show) Execute(args []string) (err error) {

	profiles, err := transport.RPC.GetC2Profiles(context.Background(), &clientpb.GetC2ProfilesReq{})
	if err != nil {
		return log.Error(err)
	}

	for i, id := range s.Args.ProfileID {
		for _, profile := range profiles.Profiles {
			if id == c2.GetShortID(profile.ID) {
				c2.PrintProfileSummaryLong(profile)
				if i < len(s.Args.ProfileID)-1 {
					fmt.Println()
				}
			}
		}
	}
	return
}
