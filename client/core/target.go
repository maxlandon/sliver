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
	"fmt"
	"strconv"

	"github.com/bishopfox/sliver/protobuf/clientpb"
)

var (

	// ActiveTarget - Either the active session or the active beacon
	ActiveTarget = &activeTarget{}
)

// Target - An interface allowing us to transparently use the active
// target, regardless of it being a Session or a Beacon.
type Target interface {
	// Base
	ID() string
	Name() string

	// Type
	IsSession() bool
	IsBeacon() bool

	// Info
	Hostname() string
	UUID() string
	Username() string
	UID() string
	GID() string
	PID() int32
	OS() string
	Arch() string
	Filename() string
	Version() string
	Evasion() bool
	WorkingDirectory() string

	// State
	State() clientpb.State
	Unavailable() error
	Burned() bool

	// Underlying
	Session() *clientpb.Session
	SetSession(sess *clientpb.Session)
	Beacon() *clientpb.Beacon
	SetBeacon(beacon *clientpb.Beacon)

	// Transport
	ActiveC2() string
	Transport() string
	LastCheckin() int64
	RemoteAddress() string
	ProxyURL() string

	// Session
	ReconnectInterval() int64
	PollTimeout() int64
	Extensions() []string

	// Beacon
	Interval() int64
	Jitter() int64
	NextCheckin() int64
	TasksCount() int64
	TasksCountCompleted() int64
}

// activeTarget - Either an active session, or an active beacon.
// This allows to transparently use either of these in the other packages.
type activeTarget struct {
	session *clientpb.Session
	beacon  *clientpb.Beacon
}

// Common -----------------------------------------------
func (t *activeTarget) ID() string {
	if t.session == nil && t.beacon == nil {
		return ""
	}
	if t.session != nil {
		return strconv.Itoa(int(t.session.ID))
	}
	return t.beacon.ID
}

func (t *activeTarget) ShortID() string {
	if t.session == nil && t.beacon == nil {
		return ""
	}
	if t.session != nil {
		return strconv.Itoa(int(t.session.ID))
	}
	var shortID string
	if len(t.beacon.ID) < 8 {
		shortID = shortID[:len(t.beacon.ID)]
	} else {
		shortID = t.beacon.ID[:8]
	}
	return shortID
}

func (t *activeTarget) Name() string {
	if t.session == nil && t.beacon == nil {
		return ""
	}
	if t.session != nil {
		return t.session.Name
	}
	return t.beacon.Name
}

func (t *activeTarget) Hostname() string {
	if t.session == nil && t.beacon == nil {
		return ""
	}
	if t.session != nil {
		return t.session.Hostname
	}
	return t.beacon.Hostname
}

func (t *activeTarget) UUID() string {
	if t.session == nil && t.beacon == nil {
		return ""
	}
	if t.session != nil {
		return t.session.UUID
	}
	return t.beacon.UUID
}

func (t *activeTarget) Username() string {
	if t.session == nil && t.beacon == nil {
		return ""
	}
	if t.session != nil {
		return t.session.Username
	}
	return t.beacon.Username
}

func (t *activeTarget) UID() string {
	if t.session == nil && t.beacon == nil {
		return ""
	}
	if t.session != nil {
		return t.session.UID
	}
	return t.beacon.UID
}

func (t *activeTarget) GID() string {
	if t.session == nil && t.beacon == nil {
		return ""
	}
	if t.session != nil {
		return t.session.GID
	}
	return t.beacon.GID
}

func (t *activeTarget) PID() int32 {
	if t.session == nil && t.beacon == nil {
		return 0
	}
	if t.session != nil {
		return t.session.PID
	}
	return t.beacon.PID
}

func (t *activeTarget) OS() string {
	if t.session == nil && t.beacon == nil {
		return ""
	}
	if t.session != nil {
		return t.session.OS
	}
	return t.beacon.OS
}

func (t *activeTarget) Arch() string {
	if t.session == nil && t.beacon == nil {
		return ""
	}
	if t.session != nil {
		return t.session.Arch
	}
	return t.beacon.Arch
}

func (t *activeTarget) Transport() string {
	if t.session == nil && t.beacon == nil {
		return ""
	}
	if t.session != nil {
		return t.session.Transport
	}
	return t.beacon.Transport
}

func (t *activeTarget) RemoteAddress() string {
	if t.session == nil && t.beacon == nil {
		return ""
	}
	if t.session != nil {
		return t.session.RemoteAddress
	}
	return t.beacon.RemoteAddress
}

func (t *activeTarget) Filename() string {
	if t.session == nil && t.beacon == nil {
		return ""
	}
	if t.session != nil {
		return t.session.Filename
	}
	return t.beacon.Filename
}

func (t *activeTarget) LastCheckin() int64 {
	if t.session == nil && t.beacon == nil {
		return 0
	}
	if t.session != nil {
		return t.session.LastCheckin
	}
	return t.beacon.LastCheckin
}

func (t *activeTarget) ActiveC2() string {
	if t.session == nil && t.beacon == nil {
		return ""
	}
	if t.session != nil {
		return t.session.ActiveC2
	}
	return t.beacon.ActiveC2
}

func (t *activeTarget) Version() string {
	if t.session == nil && t.beacon == nil {
		return ""
	}
	if t.session != nil {
		return t.session.Version
	}
	return t.beacon.Version
}

func (t *activeTarget) Evasion() bool {
	if t.session == nil && t.beacon == nil {
		return false
	}
	if t.session != nil {
		return t.session.Evasion
	}
	return t.beacon.Evasion
}

func (t *activeTarget) State() clientpb.State {
	if t.session == nil && t.beacon == nil {
		return clientpb.State_Dead
	}
	if t.session != nil {
		return t.session.State
	}
	return t.beacon.State
}

func (t *activeTarget) Unavailable() (err error) {
	var state clientpb.State
	if t.session != nil {
		state = t.session.State
	} else if t.beacon != nil {
		state = t.beacon.State
	}
	if t.session != nil {
		if state == clientpb.State_Dead {
			return fmt.Errorf("Cannot use command: session is dead")
		}
		if state == clientpb.State_Sleep {
			return fmt.Errorf("Cannot use command: session is sleeping")
		}
		if state == clientpb.State_Switching {
			return fmt.Errorf("Cannot use command: session is switching its transport and currently disconnected")
		}
	}
	return nil
}

func (t *activeTarget) ProxyURL() string {
	if t.session == nil && t.beacon == nil {
		return ""
	}
	if t.session != nil {
		return t.session.ProxyURL
	}
	return t.beacon.ProxyURL
}

func (t *activeTarget) Burned() bool {
	if t.session == nil && t.beacon == nil {
		return false
	}
	if t.session != nil {
		return t.session.Burned
	}
	return t.beacon.Burned
}

func (t *activeTarget) WorkingDirectory() string {
	if t.session == nil && t.beacon == nil {
		return ""
	}
	if t.session != nil {
		return t.session.WorkingDirectory
	}
	return t.beacon.WorkingDirectory
}

// Type -----------------------------------------------
func (t *activeTarget) IsSession() bool {
	if t.session != nil {
		return true
	}
	return false
}

func (t *activeTarget) IsBeacon() bool {
	if t.beacon != nil {
		return true
	}
	return false
}

// Underlying -----------------------------------------------
func (t *activeTarget) Targets() (sess *clientpb.Session, beacon *clientpb.Beacon) {
	return t.session, t.beacon
}

func (t *activeTarget) Session() *clientpb.Session {
	return t.session
}

func (t *activeTarget) SetSession(sess *clientpb.Session) *clientpb.Session {
	t.session = sess
	return t.session
}

func (t *activeTarget) Beacon() *clientpb.Beacon {
	return t.beacon
}

func (t *activeTarget) SetBeacon(beacon *clientpb.Beacon) *clientpb.Beacon {
	t.beacon = beacon
	return t.beacon
}

// Session -----------------------------------------------
func (t *activeTarget) ReconnectInterval() int64 {
	if t.session != nil {
		return t.session.ReconnectInterval
	}
	return -1
}

func (t *activeTarget) PollTimeout() int64 {
	if t.session != nil {
		return t.session.PollTimeout
	}
	return -1
}

func (t *activeTarget) Extensions() []string {
	if t.session != nil {
		return t.session.Extensions
	}
	return []string{}
}

// Beacon -----------------------------------------------
func (t *activeTarget) Interval() int64 {
	if t.beacon != nil {
		return t.beacon.Interval
	}
	return -1
}

func (t *activeTarget) Jitter() int64 {
	if t.beacon != nil {
		return t.beacon.Jitter
	}
	return -1
}

func (t *activeTarget) NextCheckin() int64 {
	if t.beacon != nil {
		return t.beacon.NextCheckin
	}
	return -1
}

func (t *activeTarget) TasksCount() int64 {
	if t.beacon != nil {
		return t.beacon.TasksCount
	}
	return -1
}

func (t *activeTarget) TasksCountCompleted() int64 {
	if t.beacon != nil {
		return t.beacon.TasksCountCompleted
	}
	return -1
}
