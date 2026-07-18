package rpc

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
	"runtime"
	"time"

	"github.com/bishopfox/sliver/client/version"
	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// operatorOnlineWindow is how recently a user must have been seen (i.e. have made
// an authenticated RPC) to be reported as "online". This is a deliberately ROUGH
// liveness signal derived from LastSeen rather than exact connection state:
// Sliver's live-client registry (core.Clients) only drops an operator when its
// Events stream cleanly signals context cancellation, which does NOT happen on
// every console-close path, so a lingering registry entry would pin a departed
// operator "online" for the life of the server process. LastSeen is refreshed on
// every authenticated RPC and ages on its own once the operator stops calling, so
// recency gives a self-healing (if approximate) status with no teardown hook.
//
// Caveat: an idle-but-connected console (open, but issuing no RPCs) stops
// refreshing LastSeen and tips to offline after this window. Keeping such sessions
// marked online would require a periodic keepalive RPC (a separate change).
const operatorOnlineWindow = 60 * time.Second

// GetVersion - Get the server version
func (rpc *Server) GetVersion(ctx context.Context, _ *commonpb.Empty) (*clientpb.Version, error) {
	dirty := version.GitDirty != ""
	semVer := version.SemanticVersion()
	compiled, _ := version.Compiled()
	return &clientpb.Version{
		Major:      int32(semVer[0]),
		Minor:      int32(semVer[1]),
		Patch:      int32(semVer[2]),
		Commit:     version.GitCommit,
		Dirty:      dirty,
		CompiledAt: compiled.Unix(),
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
	}, nil
}

// GetUsers returns the list of teamserver users and their status.
func (ts *Server) GetUsers(context.Context, *commonpb.Empty) (*clientpb.Users, error) {
	// Fetch users from the teamserver user database.
	users, err := ts.team.Users()

	userspb := make([]*clientpb.User, len(users))
	for i, user := range users {
		userspb[i] = &clientpb.User{
			Name:     user.Name,
			Online:   isOperatorOnline(user.LastSeen),
			LastSeen: user.LastSeen.Unix(),
			Clients:  int32(user.Clients),
		}
	}

	return &clientpb.Users{Users: userspb}, err
}

// isOperatorOnline reports a rough liveness status for a user derived from how
// recently they were last seen: any authenticated RPC refreshes LastSeen, so a
// user active within operatorOnlineWindow reads as online and otherwise decays to
// offline on its own. A zero LastSeen (never authenticated) is always offline.
func isOperatorOnline(lastSeen time.Time) bool {
	if lastSeen.IsZero() {
		return false
	}
	return time.Since(lastSeen) < operatorOnlineWindow
}
