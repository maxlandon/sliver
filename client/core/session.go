package core

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
	"strconv"
	"time"

	"github.com/bishopfox/sliver/client/constants"
	"github.com/bishopfox/sliver/client/transport"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/rpcpb"
)

var (
	// Console - At startup the console has passed itself to this package, so that
	// we can question the application parser for timeout/request options.
	// Console *gonsole.Console

	//SessionHistoryFunc - Will pass the session history to the console package.
	// This is needed as we cannot import the console package, which contains histories.
	SessionHistoryFunc func(commands []string)

	// UserHistoryFunc - Same principle: a function that is called when the context
	// is switched back from a Session to the server menu
	UserHistoryFunc func()
)

// SetActiveTarget - Sets a session/beacon as active and
// pulls out all informations needed by the console.
func SetActiveTarget(sess *clientpb.Session, beacon *clientpb.Beacon) {

	// We set the session as active...
	if sess != nil {
		ActiveTarget.session = sess
	}

	// Or the beacon.
	if beacon != nil {
		ActiveTarget.beacon = beacon
	}

	// Then switch the console context
	Console.SwitchMenu(constants.SliverMenu)

	// Hide Windows commands if this implant is not Windows-based
	if ActiveTarget.OS() != "windows" {
		Console.HideCommands(constants.SliverWinHelpGroup)
	} else {
		Console.ShowCommands(constants.SliverWinHelpGroup)
	}

	// Hide WireGuard commands if not the current transport
	if ActiveTarget.Transport() != "wg" {
		Console.HideCommands(constants.WireGuardGroup)
	} else {
		Console.ShowCommands(constants.WireGuardGroup)
	}

	// Then we get the history
	sessionHistory := GetActiveSessionHistory()
	SessionHistoryFunc(sessionHistory)
}

// UnsetActiveSession - We have backgrounded from a Sliver session, or it died.
func UnsetActiveSession() {

	// Refresh the user-wide history
	UserHistoryFunc()

	// Switch the console context
	Console.SwitchMenu(constants.ServerMenu)

	// We don't have a working Sliver object anymore.
	if ActiveTarget.Session() != nil {
		ActiveTarget.session = nil
	}
	if ActiveTarget.Beacon() != nil {
		ActiveTarget.beacon = nil
	}
}

// GetSession - Get session by session ID or name
func GetSession(arg string) *clientpb.Session {
	sessions, err := transport.RPC.GetSessions(context.Background(), &commonpb.Empty{})
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return nil
	}
	for _, session := range sessions.GetSessions() {
		if fmt.Sprintf("%d", session.ID) == arg {
			return session
		}
	}
	return nil
}

// GetSessionsByName - Return all sessions for an Implant by name
func GetSessionsByName(name string, rpc rpcpb.SliverRPCClient) []*clientpb.Session {
	sessions, err := rpc.GetSessions(context.Background(), &commonpb.Empty{})
	if err != nil {
		return nil
	}
	matched := []*clientpb.Session{}
	for _, session := range sessions.GetSessions() {
		if session.Name == name {
			matched = append(matched, session)
		}
	}
	return matched
}

// Request - Forge a request for the active target.
func (t *activeTarget) Request() (req *commonpb.Request) {
	req = &commonpb.Request{}

	// The current parser holds some data we want
	var parser = Console.CommandParser()
	if parser == nil {
		return req
	}

	// Get timeout
	if opt := parser.FindOptionByLongName("timeout"); opt != nil {
		if val, ok := opt.Value().(int64); ok {
			req.Timeout = val
		}
	}

	// Session/Beacon specifics
	if t.IsSession() {
		req.Async = false
		id, _ := strconv.Atoi(t.ID())
		req.SessionID = uint32(id)
	}
	if t.IsBeacon() {
		req.Async = true
		req.BeaconID = t.ID()
	}

	return
}

// SessionRequest - Forge a Request Protobuf metadata to be sent in a RPC request.
func SessionRequest(sess *clientpb.Session) (req *commonpb.Request) {
	req = &commonpb.Request{}

	if sess != nil {
		req.SessionID = sess.ID
	}

	// The current parser holds some data we want
	var parser = Console.CommandParser()
	if parser == nil {
		return req
	}

	// Get timeout
	if opt := parser.FindOptionByLongName("timeout"); opt != nil {
		if val, ok := opt.Value().(int64); ok {
			req.Timeout = val
		}
	}

	return
}

// RequestTimeout - Prepare a RPC request for the current Session.
func RequestTimeout(timeOut int) *commonpb.Request {
	timeout := int(time.Second) * timeOut
	return &commonpb.Request{
		Timeout: int64(timeout),
	}
}

func GetActiveSessionConfig() *clientpb.ImplantConfig {
	// session := ActiveTarget.Session
	// if session == nil {
	//         return nil
	// }
	c2s := []*clientpb.ImplantC2{}
	c2s = append(c2s, &clientpb.ImplantC2{
		URL:      ActiveTarget.ActiveC2(),
		Priority: uint32(0),
	})
	config := &clientpb.ImplantConfig{
		Name:    ActiveTarget.Name(),
		GOOS:    ActiveTarget.OS(),
		GOARCH:  ActiveTarget.Arch(),
		Debug:   true,
		Evasion: ActiveTarget.Evasion(),

		MaxConnectionErrors: uint32(1000),
		ReconnectInterval:   int64(60),

		Format:      clientpb.OutputFormat_SHELLCODE,
		IsSharedLib: true,
		C2:          c2s,
	}
	return config
}

// GetActiveSessionHistory - Get the command history that matches all occurences for the user_UUID session.
func GetActiveSessionHistory() []string {
	req := &clientpb.HistoryRequest{
		AllConsoles: true,
	}
	if ActiveTarget.IsSession() {
		req.Session = ActiveTarget.Session()
	}
	if ActiveTarget.IsBeacon() {
		req.Beacon = ActiveTarget.Beacon()
	}

	res, err := transport.RPC.GetHistory(context.Background(), req)
	if err != nil {
		return []string{}
	}
	return res.Sliver
}

// GetCommandTimeout - Get the current --timeout option value
func GetCommandTimeout() int64 {

	// The current parser holds some data we want
	var parser = Console.CommandParser()
	if parser == nil {
		return 60
	}

	// Get timeout
	if opt := parser.FindOptionByLongName("timeout"); opt != nil {
		if val, ok := opt.Value().(int64); ok {
			return val
		}
	}
	return 60
}
