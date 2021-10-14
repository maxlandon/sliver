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
	"time"

	"github.com/maxlandon/readline"

	"github.com/bishopfox/sliver/client/command/c2"
	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/log"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/client/util"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// List - List all or some C2 profiles
type List struct {
	Args struct {
		ProfileID []string `description:"(optional) one or more malleable C2 profiles to list only"`
	} `positional-args:"yes"`
}

// Execute - List all or some C2 profiles
func (l *List) Execute(args []string) (err error) {

	profiles, err := transport.RPC.GetMalleables(context.Background(), &clientpb.GetMalleablesReq{})
	if err != nil {
		return log.Error(err)
	}
	if len(profiles.Profiles) == 0 {
		log.Infof("No Malleable profiles. Create one with `malleable dialer|listener <c2> <addr> --options`")
		return
	}
	var filtered []*sliverpb.Malleable
	for _, id := range l.Args.ProfileID {
		for _, p := range profiles.Profiles {
			if c2.GetShortID(p.ID) == id {
				filtered = append(filtered, p)
			}
		}
	}

	var list = []*sliverpb.Malleable{}
	if len(filtered) > 0 {
		list = filtered
	} else {
		list = profiles.Profiles
	}

	printMalleables(list)

	return
}

func printMalleables(profiles []*sliverpb.Malleable) {

	// If we are in the server context, print all of them as once
	if core.ActiveTarget.ID() == "" {
		printProfilesWithTitle("", profiles)
		return
	}

	// If we are in a session, try a separate, first table for
	// profiles that belong to this session context only.
	var sessionProfiles = []*sliverpb.Malleable{}
	var otherProfiles = []*sliverpb.Malleable{}
	for _, p := range profiles {
		if p.ContextSessionID == core.ActiveTarget.UUID() {
			sessionProfiles = append(sessionProfiles, p)
		} else {
			otherProfiles = append(otherProfiles, p)
		}
	}

	// If any session profile, print them in a separate table
	if len(sessionProfiles) > 0 {
		printProfilesWithTitle("Session Context", sessionProfiles)
	}

	// Add another table with a title or just print them all in one,
	// depending on if we have either both of them, or one of them.
	if len(sessionProfiles) == 0 && len(otherProfiles) > 0 {
		printProfilesWithTitle("", otherProfiles)
	} else if len(sessionProfiles) > 0 && len(otherProfiles) > 0 {
		fmt.Println()
		printProfilesWithTitle("Other Profiles", otherProfiles)
	}
}

func printProfilesWithTitle(title string, profiles []*sliverpb.Malleable) {

	table := util.NewTable(readline.Yellow(title))
	// TODO: add Credentials  with "user/pass" or "api/pass" or "type" indication => devise
	headers := []string{"ID", "Channel", "Direction", "Address", "Name", "Errs/Reconnect", "Jit/Interval", "SSH Comms"}
	headLen := []int{0, 0, 0, 0, 0, 0, 0, 0}
	table.SetColumns(headers, headLen)

	for _, p := range profiles {

		id := c2.GetShortID(p.ID)
		channel := p.C2.String()
		dir := p.Direction.String()
		address := readline.Bold(c2.FullTargetPath(p))
		name := p.Name

		// Timeouts
		var timeouts string
		var jitInt string
		if p.Type == sliverpb.C2Type_Beacon {
			jitInt = fmt.Sprintf("%-3s / %3s", time.Duration(p.Jitter), time.Duration(p.Interval))
			timeouts = fmt.Sprintf("%d / %s", p.MaxConnectionErrors, time.Duration(p.Interval))
		} else {
			timeouts = fmt.Sprintf("%-4d / %4s", p.MaxConnectionErrors, time.Duration(p.Interval))
		}

		// Comm
		var comms string
		if p.CommDisabled {
			comms = readline.YELLOW + "no" + readline.RESET
		} else {
			comms = readline.GREEN + "yes" + readline.RESET
		}

		// Add to table
		table.AppendRow([]string{id, channel, dir, address, name, timeouts, jitInt, comms})
	}

	fmt.Printf(table.Output())
}
