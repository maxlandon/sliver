package models

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
	"time"

	"github.com/gofrs/uuid"
	"google.golang.org/protobuf/proto"
	"gorm.io/gorm"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// Transport - A C2 profile loaded onto an implant as an available transport.
type Transport struct {
	ID             uuid.UUID `gorm:"primaryKey;->;<-:create;type:uuid;"`
	CreatedAt      time.Time `gorm:"->;<-:create;"`
	ImplantBuildID uuid.UUID // Compile-time transports
	SessionID      uuid.UUID // Runtime transports

	Priority  int
	Running   bool
	ProfileID uuid.UUID
	Profile   *C2Profile
}

// ToProtobuf - The transport needs to be sent to a client console
func (t *Transport) ToProtobuf() *clientpb.Transport {
	transport := &clientpb.Transport{
		ID:      t.ID.String(),
		Order:   int32(t.Priority),
		Running: t.Running,
		Profile: t.Profile.ToProtobuf(),
	}

	return transport
}

// BeforeCreate - GORM hook
func (t *Transport) BeforeCreate(tx *gorm.DB) (err error) {
	// Only create a new UUID if there isn't one already.
	if t.ID == uuid.Nil {
		t.ID, err = uuid.NewV4()
		if err != nil {
			return err
		}
	}
	t.CreatedAt = time.Now()
	return nil
}

// C2Profile - A complete C2 profile to be compiled into/ loaded by an implant.
type C2Profile struct {
	ID        uuid.UUID `gorm:"primaryKey;->;<-:create;type:uuid;"`
	CreatedAt time.Time `gorm:"->;<-:create;"`

	ImplantBuildID   uuid.UUID
	ContextSessionID uuid.UUID
	JobID            uuid.UUID
	Transports       []*Transport `gorm:"many2many:profile_transports"` // Maybe not needed ?

	Name      string
	Type      sliverpb.C2Type
	Channel   sliverpb.C2Channel
	Direction sliverpb.C2Direction
	Hostname  string
	Port      uint32
	Path      string

	// Technicals
	PollTimeout         int64
	MaxConnectionErrors int32
	IsFallback          bool
	Persistent          bool
	Active              bool
	CommDisabled        bool // Use the SSH-protocol based multiplexing on top of this C2 channel

	// Beaconing
	Beacon   bool
	Interval int64
	Jitter   int64

	// Control Endpoints
	ControlPort     uint32 // A generic ControlPort available to some C2 stacks (like Wireguard)
	KeyExchangePort uint32 // Generic key-exchange port for some protocols (like Wireguard)

	// HTTP related
	HTTP     C2ProfileHTTP // Needs to be unmarshaled to a sliverpb.C2ProfileHTTP
	ProxyURL string

	// Identity & Security. TODO: Credential model integration
	// C2 Core
	CACertPEM         []byte
	CertPEM           []byte
	KeyPEM            []byte
	ServerFingerprint []byte
	// Advanced
	ControlServerCert []byte
	ControlClientKey  []byte

	// If compiled with legacy generate, this is just a profile for compilation
	// We will not include those in most completions/commands that manipulate profiles.
	// Exception made of transports commands, which need to have access to those.
	Anonymous bool
}

// BeforeCreate - GORM hook
func (p *C2Profile) BeforeCreate(tx *gorm.DB) (err error) {
	// Only create a new UUID if there isn't one already.
	if p.ID == uuid.Nil {
		p.ID, err = uuid.NewV4()
		if err != nil {
			return err
		}
	}
	p.CreatedAt = time.Now()
	return nil
}

// ToProtobuf - Convert ImplantConfig to protobuf equiv
func (p *C2Profile) ToProtobuf() *sliverpb.C2Profile {
	profile := &sliverpb.C2Profile{
		// Core
		ID:               p.ID.String(),
		ContextSessionID: p.ContextSessionID.String(),
		Name:             p.Name,
		Hostname:         p.Hostname,
		Port:             p.Port,
		Type:             p.Type,
		C2:               p.Channel,
		Direction:        p.Direction,
		// Technicals
		PollTimeout:         p.PollTimeout,
		MaxConnectionErrors: p.MaxConnectionErrors,
		IsFallback:          p.IsFallback,
		Persistent:          p.Persistent,
		Active:              p.Active,
		CommDisabled:        p.CommDisabled,
		// Control Endpoints
		ControlPort:     p.ControlPort,
		KeyExchangePort: p.KeyExchangePort,
		// Beaconing
		Interval: p.Interval,
		Jitter:   p.Jitter,
		// HTTP:
		HTTP:     p.HTTP.ToProtobuf(),
		ProxyURL: p.ProxyURL,
		// Security & Identity
		Credentials: &sliverpb.Credentials{
			CACertPEM:         []byte(p.CACertPEM),
			CertPEM:           []byte(p.CertPEM),
			KeyPEM:            []byte(p.KeyPEM),
			ServerFingerprint: []byte(p.ServerFingerprint),
			ControlServerCert: []byte(p.ControlServerCert),
			ControlClientKey:  []byte(p.ControlClientKey),
		},
	}

	return profile

}

// C2ProfileFromProtobuf - Convert C2 profile into Protobuf
func C2ProfileFromProtobuf(p *sliverpb.C2Profile) (profile *C2Profile) {
	profile = &C2Profile{
		// Core
		ID:               uuid.FromStringOrNil(p.ID),
		ContextSessionID: uuid.FromStringOrNil(p.ContextSessionID),
		Name:             p.Name,
		Hostname:         p.Hostname,
		Port:             p.Port,
		Type:             p.Type,
		Channel:          p.C2,
		Direction:        p.Direction,
		// Technicals
		PollTimeout:         p.PollTimeout,
		MaxConnectionErrors: p.MaxConnectionErrors,
		IsFallback:          p.IsFallback,
		Active:              p.Active,
		CommDisabled:        p.CommDisabled,
		Persistent:          p.Persistent,
		// Control Endpoints
		ControlPort:     p.ControlPort,
		KeyExchangePort: p.KeyExchangePort,
		// Beaconing
		Interval: p.Interval,
		Jitter:   p.Jitter,
		// HTTP:
		ProxyURL: p.ProxyURL,
	}

	// Security & Identity
	if p.Credentials != nil {
		profile.CACertPEM = []byte(p.Credentials.CACertPEM)
		profile.CertPEM = []byte(p.Credentials.CertPEM)
		profile.KeyPEM = []byte(p.Credentials.KeyPEM)
		profile.ServerFingerprint = []byte(p.Credentials.ServerFingerprint)
		profile.ControlServerCert = []byte(p.Credentials.ControlServerCert)
		profile.ControlClientKey = []byte(p.Credentials.ControlClientKey)
	}

	if p.HTTP != nil {
		httpProfileData, _ := proto.Marshal(p.HTTP)
		profile.HTTP = C2ProfileHTTP{
			ID:   uuid.FromStringOrNil(p.HTTP.ID),
			Data: httpProfileData,
		}
	} else {
		p.HTTP = &sliverpb.C2ProfileHTTP{}
	}

	return profile
}

type C2ProfileHTTP struct {
	ID          uuid.UUID `gorm:"primaryKey;->;<-:create;type:uuid;"`
	C2ProfileID uuid.UUID

	UserAgent string // For search purposes and quick access
	Data      []byte // Needs to be unmarshaled to a sliverpb.C2ProfileHTTP
}

// ToProtobuf - Get a protobuf version  of this HTTP profile,
// so that we can compile it more easily, or send it on the wire
func (h *C2ProfileHTTP) ToProtobuf() *sliverpb.C2ProfileHTTP {
	p := &sliverpb.C2ProfileHTTP{
		ID:        h.ID.String(),
		UserAgent: h.UserAgent,
	}
	// Unmarshal the raw Protobuf configuration,
	// which will be used either by implants or
	// by users setting them in their consoles
	proto.Unmarshal([]byte(h.Data), p)

	return p
}

// BeforeCreate - GORM hook
func (h *C2ProfileHTTP) BeforeCreate(tx *gorm.DB) (err error) {
	h.ID, err = uuid.NewV4()
	if err != nil {
		return err
	}
	return nil
}
