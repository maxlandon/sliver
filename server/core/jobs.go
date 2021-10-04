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
	"sync"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/gofrs/uuid"

	consts "github.com/bishopfox/sliver/client/constants"
)

var (
	// Jobs - Holds pointers to all the current jobs
	Jobs = &jobs{
		active:          map[string]*Job{},
		sessionCounters: map[string]int{},
		mutex:           &sync.RWMutex{},
	}

	// StartPersistentSessionJobs - This function is mapped at startup
	// time by the c2 package, which passes its function of the same name.
	// This function is then called by the registerSessionHandler in the
	// handlers package. This is made like this to avoid circular imports.
	StartPersistentSessionJobs func(session *Session) error
)

// Job - Background jobs on the server and sessions.
type Job struct {
	// Base
	ID              uuid.UUID
	SessionID       string
	SessionName     string
	SessionUsername string
	Name            string
	Description     string
	Order           int

	// Job concurrency tools
	JobCtrl chan bool
	Ticker  *time.Ticker

	// C2
	Profile  *sliverpb.C2Profile // All handler details
	cleanups []func() error      // All cleanup functions that have been registered with this job
}

// RegisterCleanup - Add a cleanup function to this job. This function will be called
// (in the INVERSE order in which it was registered) when the job receives the kill signal.
func (j *Job) RegisterCleanup(cleanup func() error) {
	j.cleanups = append(j.cleanups, cleanup)
}

// HandleCleanup - Waits for the job Ctrl to be closed, and performs all base
// and user-specified cleanup tasks and logs any errors arising from them.
func (j *Job) HandleCleanup() {
	<-j.JobCtrl
	j.Ticker.Stop()

	// Successively perform all registered cleanup tasks IN REVERSE ORDER:
	// The logic is: we must close the layers in the inverse order they have setup
	for i := len(j.cleanups) - 1; i >= 0; i-- {
		cleanup := j.cleanups[i]
		err := cleanup()
		if err != nil {
			// TODO: Log error here
		}
	}

	// Unregister the job and notify clients
	Jobs.Remove(j)
}

// ToProtobuf - The job info to be passed to a client
func (j *Job) ToProtobuf() *clientpb.Job {
	return &clientpb.Job{
		ID:              j.ID.String(),
		SessionID:       j.SessionID,
		SessionName:     j.SessionName,
		SessionUsername: j.SessionUsername,

		Name:        j.Name,
		Description: j.Description,
		Order:       int32(j.Order),

		Profile: j.Profile,
	}
}

// jobs - Holds refs to all active jobs
type jobs struct {
	active          map[string]*Job
	sessionCounters map[string]int
	mutex           *sync.RWMutex
}

// All - Return a list of all jobs
func (j *jobs) All() []*Job {
	j.mutex.RLock()
	defer j.mutex.RUnlock()
	all := []*Job{}
	for _, job := range j.active {
		all = append(all, job)
	}
	return all
}

// Add - Add a job to the hive (atomically)
func (j *jobs) Add(job *Job) {
	j.mutex.Lock()
	defer j.mutex.Unlock()
	j.active[job.ID.String()] = job
	EventBroker.Publish(Event{
		Job:       job,
		EventType: consts.JobStartedEvent,
	})
}

// Remove - Remove a job
func (j *jobs) Remove(job *Job) {
	j.mutex.Lock()
	defer j.mutex.Unlock()
	delete(j.active, job.ID.String())

	var description string

	// If job is a C2 handler, populate event description
	if job.Profile != nil {
		var host string
		if job.Profile.Port > 0 {
			host = fmt.Sprintf("%s:%d%s", job.Profile.Hostname, job.Profile.Port, job.Profile.Path)
		} else {
			host = fmt.Sprintf("%s%s", job.Profile.Hostname, job.Profile.Path)
		}
		description = fmt.Sprintf(job.Profile.C2.String(), job.Profile.C2.Type, host, GetShortID(job.ID.String()))
	}

	// Else, simply use the job description as set when declared by the system
	if job.Profile == nil {
		description = job.Description
	}

	// Publish the job stopped event
	EventBroker.Publish(Event{
		Job:       job,
		EventType: consts.JobStoppedEvent,
		Data:      []byte(description),
	})
}

// Get - Get a JobNew
func (j *jobs) Get(jobID string) *Job {
	j.mutex.RLock()
	defer j.mutex.RUnlock()
	return j.active[jobID]
}

// GetShortID - Get a shorter 8 bits ID
func GetShortID(ID string) (short string) {
	if len(ID) < 8 {
		short = ID
	} else {
		short = ID[:8]
	}
	return
}

// NextJobID - Returns an incremental nonce as an id
func (j *jobs) NextSessionJobCount(session *Session) int {

	// If no session, the job is running on the server
	if session == nil {
		return NextServerJobID()
	}

	// Else, create/increase the counter for the corresponding session.
	var sessCount int
	var found bool
	if sessCount, found = j.sessionCounters[session.HostUUID+session.Name+session.Username]; found {
		j.sessionCounters[session.HostUUID+session.Name+session.Username] = 0
		sessCount = j.sessionCounters[session.HostUUID+session.Name+session.Username]
	}

	sessCount = sessCount + 1
	return sessCount
}

var serverJobID = 0

// NextServerJobID - Returns an incremental nonce as an id
func NextServerJobID() int {
	newID := serverJobID + 1
	serverJobID++
	return newID
}
