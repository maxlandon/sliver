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
	"time"

	"github.com/maxlandon/readline"

	c2cmds "github.com/bishopfox/sliver/client/command/c2"
	"github.com/bishopfox/sliver/client/core"
	"github.com/bishopfox/sliver/client/transport"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// MalleableIDs - Returns IDs of all Malleable C2 profiles, along with a description
func MalleableIDs() (comps []*readline.CompletionGroup) {

	profiles, err := transport.RPC.GetMalleables(context.Background(), &clientpb.GetMalleablesReq{
		Request: core.ActiveTarget.Request(),
	})
	if err != nil {
		return
	}

	// Just return all C2s if we are in the server menu
	if core.ActiveTarget.ID() == "" {
		allC2s := OutOfContextMalleableIDs(profiles.Profiles)
		allC2s.Name = "all C2 profiles"
		comps = append(comps, allC2s)
		return
	}

	// else, return 2 groups:
	// one of profiles linked to the current session,
	comps = append(comps, ContextSessionMalleableIDs(profiles.Profiles))

	// and one for the others.
	comps = append(comps, OutOfContextMalleableIDs(profiles.Profiles))

	return
}

// ContextSessionMalleableIDs - All C2 profiles linked to the current Session context, if any.
func ContextSessionMalleableIDs(profiles []*sliverpb.Malleable) (contextC2s *readline.CompletionGroup) {

	var contextProfiles = []*sliverpb.Malleable{}
	for _, prof := range profiles {
		if prof.ContextSessionID == core.ActiveTarget.ID() {
			contextProfiles = append(contextProfiles, prof)
		}
	}

	// Malleable profiles that match the current session context in a single group
	contextC2s = &readline.CompletionGroup{
		Name:         "session-related C2s",
		Descriptions: map[string]string{},
		DisplayType:  readline.TabDisplayList,
	}

	// Make sessions and beacons in subgroups
	sortedContextC2s := sortMalleableProfilesByType(contextProfiles)
	sessionC2s := getSessionProfiles(sortedContextC2s)
	sessDescs := getSessionDescriptions(sessionC2s)
	for id, desc := range sessDescs {
		contextC2s.Suggestions = append(contextC2s.Suggestions, id)
		contextC2s.Descriptions[id] = desc
	}
	beaconC2s := getBeaconProfiles(sortedContextC2s)
	beaconDescs := getSessionDescriptions(beaconC2s)
	for id, desc := range beaconDescs {
		contextC2s.Suggestions = append(contextC2s.Suggestions, id)
		contextC2s.Descriptions[id] = desc
	}

	return
}

// OutOfContextMalleableIDs - All Malleable profiles that are not linked to the current Session, if any
func OutOfContextMalleableIDs(profiles []*sliverpb.Malleable) (otherC2s *readline.CompletionGroup) {

	var otherProfiles = []*sliverpb.Malleable{}
	for _, prof := range profiles {
		if prof.ContextSessionID != core.ActiveTarget.ID() {
			otherProfiles = append(otherProfiles, prof)
		}
	}

	otherC2s = &readline.CompletionGroup{
		Name:         "other C2s",
		Descriptions: map[string]string{},
		DisplayType:  readline.TabDisplayList,
	}
	// Make sessions and beacons in subgroups
	sortedOtherC2s := sortMalleableProfilesByType(otherProfiles)
	otherSessionsC2s := getSessionProfiles(sortedOtherC2s)
	otherSessDescs := getSessionDescriptions(otherSessionsC2s)
	for id, desc := range otherSessDescs {
		otherC2s.Suggestions = append(otherC2s.Suggestions, id)
		otherC2s.Descriptions[id] = desc
	}
	otherBeaconC2s := getBeaconProfiles(sortedOtherC2s)
	otherBeaconDescs := getBeaconDescriptions(otherBeaconC2s)
	for id, desc := range otherBeaconDescs {
		otherC2s.Suggestions = append(otherC2s.Suggestions, id)
		otherC2s.Descriptions[id] = desc
	}

	return
}

func getSessionProfiles(profiles []*sliverpb.Malleable) (sessions []*sliverpb.Malleable) {
	for _, p := range profiles {
		if p.Type == sliverpb.C2Type_Session {
			sessions = append(sessions, p)
		}
	}
	return
}

func getBeaconProfiles(profiles []*sliverpb.Malleable) (beacons []*sliverpb.Malleable) {
	for _, p := range profiles {
		if p.Type == sliverpb.C2Type_Beacon {
			beacons = append(beacons, p)
		}
	}
	return
}

func getSessionDescriptions(sessions []*sliverpb.Malleable) (descriptions map[string]string) {
	descriptions = map[string]string{}
	for _, c2 := range sessions {
		// Left hand side
		direction := ""
		if c2.Direction == sliverpb.C2Direction_Bind {
			direction = "-->  "
		} else {
			direction = "<--  "
		}
		protocolDirPath := fmt.Sprintf("%-9s %s ", c2.C2, direction) + c2cmds.FullTargetPath(c2)

		// Right hand side
		name := fmt.Sprintf("%15s", "["+c2.Name+"] ")
		connSettings := fmt.Sprintf("%-8s / %5s", time.Duration(c2.Interval), time.Duration(c2.PollTimeout))
		sessionInfo := fmt.Sprintf("(S) %8s", connSettings)
		maxErrors := fmt.Sprintf("  MaxErr: %-5d", c2.MaxErrors)

		rightHand := name + sessionInfo + maxErrors

		sWidth := readline.GetTermWidth()
		pad := getPromptPad(sWidth-20, len(protocolDirPath), len(rightHand))
		description := readline.DIM + protocolDirPath + pad + rightHand + readline.RESET

		descriptions[c2cmds.GetShortID(c2.ID)] = description
	}
	// ehl73ejk  HTTPS --> 134.232.43.234:443/evildomain.com/subscribe?test     [StealthBanking] - [S] 2m / 30s   MaxErr: 30

	return
}

func getBeaconDescriptions(beacons []*sliverpb.Malleable) (descriptions map[string]string) {
	descriptions = map[string]string{}
	for _, c2 := range beacons {
		// Left hand side
		direction := ""
		if c2.Direction == sliverpb.C2Direction_Bind {
			direction = "-->  "
		} else {
			direction = "<--  "
		}
		protocolDirPath := fmt.Sprintf("%-9s %s ", c2.C2, direction) + c2cmds.FullTargetPath(c2)

		// Right hand side
		name := fmt.Sprintf("%15s", "["+c2.Name+"] ")
		connSettings := fmt.Sprintf("%-8s / %5s", time.Duration(c2.Interval), time.Duration(c2.Jitter))
		sessionInfo := fmt.Sprintf("(B) %8s", connSettings)
		maxErrors := fmt.Sprintf("  MaxErr: %-5d", c2.MaxErrors)

		rightHand := name + sessionInfo + maxErrors

		sWidth := readline.GetTermWidth()
		pad := getPromptPad(sWidth-20, len(protocolDirPath), len(rightHand))
		description := readline.DIM + protocolDirPath + pad + rightHand + readline.RESET

		descriptions[c2cmds.GetShortID(c2.ID)] = description
	}
	// ehl73ejk  HTTPS <-- 134.232.43.234:443/evildomain.com/subscribe?test   [StealthBanking] - [B] 1d:10h:2m / 30m  MaxErr: 30
	// 2gf2hmjk  MTLS  --> 192.168.43.2:443                                       [EgressInfo]   [B] 22m       / 30s  MaxErr: 2000

	return
}

func sortMalleableProfilesByType(profiles []*sliverpb.Malleable) (sorted []*sliverpb.Malleable) {
	for _, p := range profiles {
		if p.Type == sliverpb.C2Type_Session {
			sorted = append(sorted, p)
		}
	}
	for _, p := range profiles {
		if p.Type == sliverpb.C2Type_Beacon {
			sorted = append(sorted, p)
		}
	}

	return
}

func sortMalleableProfilesByDirection(profiles []*sliverpb.Malleable) (sorted []*sliverpb.Malleable) {
	for _, p := range profiles {
		if p.Direction == sliverpb.C2Direction_Bind {
			sorted = append(sorted, p)
		}
	}
	for _, p := range profiles {
		if p.Direction == sliverpb.C2Direction_Reverse {
			sorted = append(sorted, p)
		}
	}

	return
}

// MalleableIDsMTLS - Returns IDs of all MTLS Malleable C2 profiles
func MalleableIDsMTLS() (comps []*readline.CompletionGroup) {
	return
}

func getPromptPad(total, base, menu int) (pad string) {
	var padLength = total - base - menu
	for i := 0; i < padLength; i++ {
		pad += " "
	}
	return
}
