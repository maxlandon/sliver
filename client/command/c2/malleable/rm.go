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
	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// Remove - Remove one or more C2 profiles
type Remove struct {
	Args struct {
		ProfileID []string `description:"one or more malleable C2 profiles to delete" required:"1"`
	} `positional-args:"yes" required:"yes"`
}

// Execute - Remove one or more C2 profiles
func (l *Remove) Execute(args []string) (err error) {

	profiles, err := transport.RPC.GetC2Profiles(context.Background(), &clientpb.GetC2ProfilesReq{})
	if err != nil {
		return log.Error(err)
	}
	var toDelete []*sliverpb.C2Profile
	for _, p := range profiles.Profiles {
		for _, id := range l.Args.ProfileID {
			if c2.GetShortID(p.ID) == id {
				toDelete = append(toDelete, p)
			}
		}
	}

	for _, p := range toDelete {
		_, err := transport.RPC.DeleteC2Profile(context.Background(), &clientpb.DeleteC2ProfileReq{
			Profile: p,
			Request: core.ActiveTarget.Request(),
		})
		if err != nil {
			fmt.Printf(log.Errorf("Failed to delete profile %s: %s", c2.GetShortID(p.ID), err).Error())
			continue
		}
		log.Infof("Deleted profile %s (%s %s: %s)",
			c2.GetShortID(p.ID),
			p.C2.String(),
			p.Direction.String(),
			c2.FullTargetPath(p))
	}
	return
}
