package models

import (
	"time"

	"github.com/gofrs/uuid"
	"gorm.io/gorm"
)

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

type Job struct {
	ID        uuid.UUID `gorm:"primaryKey;->;<-:create;type:uuid;"`
	CreatedAt time.Time `gorm:"->;<-:create;"`

	// Precise session matching
	HostID          uuid.UUID
	ImplantBuildID  uuid.UUID // used to fetch the names and attributes of the session
	SessionName     string
	SessionUsername string

	// Info
	Name        string
	Description string
	Order       int

	// C2 & Payload related
	Profile      *Malleable
	StageImplant string // If the implant name is given, do not use the bytes
	StageBytes   []byte // If the stage is a custom stage from a client's file
}

// BeforeCreate - GORM hook
func (j *Job) BeforeCreate(tx *gorm.DB) (err error) {
	j.CreatedAt = time.Now()
	return nil
}
