package models

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
*/

import (
	"crypto/rand"
	"encoding/binary"
	"time"

	"github.com/gofrs/uuid"
	"google.golang.org/protobuf/proto"
	"gorm.io/gorm"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// Beacon - Represents a host machine
type Beacon struct {
	ID             uuid.UUID `gorm:"type:uuid;"`
	ImplantBuildID uuid.UUID `gorm:"type:uuid;"`
	CreatedAt      time.Time `gorm:"->;<-:create;"`
	SessionID      string    // Associated runtime session, if any
	// Base
	Name             string
	Hostname         string
	HostUUID         uuid.UUID `gorm:"type:uuid;"` // Host UUID
	Username         string
	UID              string
	GID              string
	OS               string
	Arch             string
	PID              int32
	Filename         string
	Version          string
	WorkingDirectory string
	State            clientpb.State
	// Beacon
	LastCheckin time.Time
	NextCheckin int64
	Tasks       []BeaconTask
	// Transports
	TransportID string
	Transport   *Transport
}

// BeforeCreate - GORM hook
func (b *Beacon) BeforeCreate(tx *gorm.DB) (err error) {
	b.CreatedAt = time.Now()
	return nil
}

// ToProtobuf - Clients ask for the beacon object
func (b *Beacon) ToProtobuf() *clientpb.Beacon {

	beacon := &clientpb.Beacon{
		ID: b.ID.String(),
		// ImplantBuildID: b.ImplantBuildID.String(),
		SessionID: b.SessionID,
		// Base
		Name:     b.Name,
		Hostname: b.Hostname,
		UUID:     b.HostUUID.String(),
		Username: b.Username,
		UID:      b.UID,
		GID:      b.GID,
		OS:       b.OS,
		Arch:     b.Arch,
		PID:      b.PID,
		Filename: b.Filename,
		Version:  b.Version,
		State:    b.State,
		// Beacon
		LastCheckin:      b.LastCheckin.Unix(),
		NextCheckin:      b.NextCheckin,
		WorkingDirectory: b.WorkingDirectory,
		// Transport
		TransportID: b.TransportID,
		Transport:   b.Transport.ToProtobuf(),
	}

	return beacon
}

func (b *Beacon) Task(envelope *sliverpb.Envelope) (*BeaconTask, error) {
	data, err := proto.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	task := &BeaconTask{
		BeaconID: b.ID,
		State:    PENDING,
		Request:  data,
	}
	return task, nil
}

// BeaconTask - Represents a host machine
const (
	PENDING   = "pending"
	SENT      = "sent"
	COMPLETED = "completed"
)

type BeaconTask struct {
	ID          uuid.UUID `gorm:"primaryKey;->;<-:create;type:uuid;"`
	EnvelopeID  int64     `gorm:"uniqueIndex"`
	BeaconID    uuid.UUID `gorm:"type:uuid;"`
	CreatedAt   time.Time `gorm:"->;<-:create;"`
	State       string
	SentAt      time.Time
	CompletedAt time.Time
	Description string
	Request     []byte // *sliverpb.Envelope
	Response    []byte // *sliverpb.Envelope
}

// BeforeCreate - GORM hook
func (b *BeaconTask) BeforeCreate(tx *gorm.DB) (err error) {
	b.ID, err = uuid.NewV4()
	if err != nil {
		return err
	}
	b.CreatedAt = time.Now()
	b.State = PENDING
	buf := make([]byte, 8)
	_, err = rand.Read(buf)
	if err != nil {
		panic(err)
	}
	b.EnvelopeID = int64(binary.LittleEndian.Uint64(buf))
	return nil
}

func (b *BeaconTask) ToProtobuf(content bool) *clientpb.BeaconTask {
	task := &clientpb.BeaconTask{
		ID:          b.ID.String(),
		BeaconID:    b.BeaconID.String(),
		CreatedAt:   int64(b.CreatedAt.UTC().Unix()),
		State:       b.State,
		SentAt:      int64(b.SentAt.UTC().Unix()),
		CompletedAt: int64(b.CompletedAt.UTC().Unix()),
		Description: b.Description,
	}
	if content {
		task.Request = b.Request
		task.Response = b.Response
	}
	return task
}
