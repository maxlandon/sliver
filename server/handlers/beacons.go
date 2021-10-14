package handlers

/*
	Sliver Implant Framework
	Copyright (C) 2021  Bishop Fox

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
	------------------------------------------------------------------------

	WARNING: These functions can be invoked by remote implants without user interaction

*/

import (
	"errors"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	sliverpb "github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/db"
	"github.com/bishopfox/sliver/server/db/models"
	"github.com/bishopfox/sliver/server/log"
	"github.com/gofrs/uuid"
	gofrsUuid "github.com/gofrs/uuid"
	"google.golang.org/protobuf/proto"
	"gorm.io/gorm"
)

var (
	beaconHandlerLog = log.NamedLogger("handlers", "beacons")
)

func beaconRegisterHandler(conn *core.Connection, data []byte) *sliverpb.Envelope {
	if conn == nil {
		return nil
	}
	reg := &sliverpb.BeaconRegister{}
	err := proto.Unmarshal(data, reg)
	if err != nil {
		beaconHandlerLog.Errorf("Error decoding beacon registration message: %s", err)
		return nil
	}
	beaconHandlerLog.Infof("Beacon registration from %s", reg.ID)
	beacon, err := db.BeaconByID(reg.ID)
	beaconHandlerLog.Debugf("Found %v err = %s", beacon, err)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		beaconHandlerLog.Errorf("Database query error %s", err)
		return nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		beacon = &models.Beacon{
			ID: uuid.FromStringOrNil(reg.ID),
		}
	}

	// Core ------------------------------------------------------------

	// beacon.ConfigID = uuid.FromStringOrNil(beaconReg.Register.ConfigID)
	beacon.Name = reg.Register.Name
	beacon.Hostname = reg.Register.Hostname
	beacon.HostUUID = uuid.FromStringOrNil(reg.Register.HostUUID)
	beacon.Username = reg.Register.Username
	beacon.UID = reg.Register.Uid
	beacon.GID = reg.Register.Gid
	beacon.OS = reg.Register.Os
	beacon.Arch = reg.Register.Arch
	beacon.PID = reg.Register.Pid
	beacon.Filename = reg.Register.Filename
	beacon.LastCheckin = conn.LastMessage
	beacon.Version = reg.Register.Version
	beacon.WorkingDirectory = reg.Register.WorkingDirectory
	beacon.State = clientpb.State_Alive.String()
	beacon.NextCheckin = reg.NextCheckin

	// Transports ------------------------------------------------------

	// Update all transports, including the running one, with their statistics
	err = core.UpdateTargetTransports(reg.Register.ActiveTransportID, beacon.ID.String(), conn, reg.Register.TransportStats)
	if err != nil {
		sessionHandlerLog.Errorf("Error when updating session transports: %s", err)
	}

	// And get the updated transport used by the Beacon
	transport, err := db.TransportByID(reg.Register.ActiveTransportID)
	if transport == nil {
		beaconHandlerLog.Errorf("Failed to find beacon transport %s", reg.Register.ActiveTransportID)
		return nil
	}
	beacon.Transport = transport

	// Registration ----------------------------------------------------

	err = db.Session().Save(&beacon).Error
	if err != nil {
		beaconHandlerLog.Errorf("Database write %s", err)
	}

	core.EventBroker.Publish(core.Event{
		Type:   clientpb.EventType_BeaconRegistered,
		Beacon: beacon,
	})

	return nil
}

func beaconTasksHandler(implantConn *core.Connection, data []byte) *sliverpb.Envelope {
	beaconTasks := &sliverpb.BeaconTasks{}
	err := proto.Unmarshal(data, beaconTasks)
	if err != nil {
		beaconHandlerLog.Errorf("Error decoding beacon tasks message: %s", err)
		return nil
	}
	go func() {
		err = db.UpdateBeaconCheckinByID(beaconTasks.ID, beaconTasks.NextCheckin)
		if err != nil {
			beaconHandlerLog.Errorf("failed to update checkin: %s", err)
		}
	}()

	// If the message contains tasks then process it as results
	// otherwise send the beacon any pending tasks. Currently we
	// don't receive results and send pending tasks at the same
	// time. We only send pending tasks if the request is empty.
	// If we send the Beacon 0 tasks it should not respond at all.
	if 0 < len(beaconTasks.Tasks) {
		beaconHandlerLog.Infof("Beacon %s returned %d task result(s)", beaconTasks.ID, len(beaconTasks.Tasks))
		go beaconTaskResults(beaconTasks.ID, beaconTasks.Tasks)
		return nil
	}

	beaconHandlerLog.Infof("Beacon %s requested pending task(s)", beaconTasks.ID)

	pendingTasks, err := db.PendingBeaconTasksByBeaconID(beaconTasks.ID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		beaconHandlerLog.Errorf("Beacon task database error: %s", err)
		return nil
	}
	tasks := []*sliverpb.Envelope{}
	for _, pendingTask := range pendingTasks {
		envelope := &sliverpb.Envelope{}
		err = proto.Unmarshal(pendingTask.Request, envelope)
		if err != nil {
			beaconHandlerLog.Errorf("Error decoding pending task: %s", err)
			continue
		}
		envelope.ID = pendingTask.EnvelopeID
		tasks = append(tasks, envelope)
		pendingTask.State = models.SENT
		pendingTask.SentAt = time.Now()
		err = db.Session().Model(&models.BeaconTask{}).Where(&models.BeaconTask{
			ID: pendingTask.ID,
		}).Updates(pendingTask).Error
		if err != nil {
			beaconHandlerLog.Errorf("Database error: %s", err)
		}
	}
	taskData, err := proto.Marshal(&sliverpb.BeaconTasks{Tasks: tasks})
	if err != nil {
		beaconHandlerLog.Errorf("Error marshaling beacon tasks message: %s", err)
		return nil
	}
	beaconHandlerLog.Infof("Sending %d task(s) to beacon %s", len(pendingTasks), beaconTasks.ID)
	return &sliverpb.Envelope{
		Type: sliverpb.MsgBeaconTasks,
		Data: taskData,
	}
}

func beaconTaskResults(beaconID string, taskEnvelopes []*sliverpb.Envelope) *sliverpb.Envelope {
	for _, envelope := range taskEnvelopes {
		dbTask, err := db.BeaconTaskByEnvelopeID(beaconID, envelope.ID)
		if err != nil {
			beaconHandlerLog.Errorf("Error finding db task: %s", err)
			continue
		}
		if dbTask == nil {
			beaconHandlerLog.Errorf("Error: nil db task!")
			continue
		}
		dbTask.State = models.COMPLETED
		dbTask.CompletedAt = time.Now()
		dbTask.Response = envelope.Data
		err = db.Session().Model(&models.BeaconTask{}).Where(&models.BeaconTask{
			ID:         dbTask.ID,
			EnvelopeID: envelope.ID,
		}).Updates(&dbTask).Error
		if err != nil {
			beaconHandlerLog.Errorf("Error updating db task: %s", err)
			continue
		}

		eventData, _ := proto.Marshal(dbTask.ToProtobuf(false))
		core.EventBroker.Publish(core.Event{
			Type: clientpb.EventType_BeaconTaskResult,
			Data: eventData,
		})
	}
	return nil
}

// switchBeacon - Create or update a beacon with the registration, and if the previous target was a session, remove it.
func switchBeacon(beacon *models.Beacon, s *core.Session, reg *sliverpb.BeaconRegister, conn *core.Connection) error {

	beaconHandlerLog.Infof("[Switching] Beacon registration from %s", reg.ID)

	// Core ------------------------------------------------------------

	beacon.ID = gofrsUuid.FromStringOrNil(reg.ID) // Always overwrite ID
	beacon.Name = reg.Register.Name
	beacon.Hostname = reg.Register.Hostname
	beacon.HostUUID = gofrsUuid.FromStringOrNil(reg.Register.HostUUID)
	beacon.Username = reg.Register.Username
	beacon.UID = reg.Register.Uid
	beacon.GID = reg.Register.Gid
	beacon.OS = reg.Register.Os
	beacon.Arch = reg.Register.Arch
	beacon.PID = reg.Register.Pid
	beacon.Filename = reg.Register.Filename
	beacon.LastCheckin = conn.LastMessage
	beacon.Version = reg.Register.Version
	// beacon.ConfigID = uuid.FromStringOrNil(reg.Register.ConfigID)
	beacon.WorkingDirectory = reg.Register.WorkingDirectory
	if s != nil {
		beacon.SessionID = s.UUID
	}
	beacon.NextCheckin = reg.NextCheckin
	beacon.TransportID = beacon.Transport.ID.String()
	beacon.State = clientpb.State_Alive.String()

	// Registration ----------------------------------------------------

	// Very important: unique constraint on envelopeID makes it easy to duplicate
	// the beacon's tasks without noticing. So we omit updating the field
	recordNotFoundErr, updateErr := db.UpdateOrCreateBeacon(beacon)
	if updateErr != nil {
		beaconHandlerLog.Errorf("Failed to create/update beacon: Database write %s", recordNotFoundErr)
	}

	// Either a registration if new beacon...
	var event core.Event
	if errors.Is(recordNotFoundErr, gorm.ErrRecordNotFound) {
		event = core.Event{
			Type:    clientpb.EventType_BeaconRegistered,
			Beacon:  beacon,
			Session: s,
		}
	} else {
		// ... Or if we have found the beacon, update it
		event = core.Event{
			Type:    clientpb.EventType_BeaconUpdated,
			Beacon:  beacon,
			Session: s,
		}
	}

	// Publish the corresponding type of event for this switch
	core.EventBroker.Publish(event)

	return nil
}
