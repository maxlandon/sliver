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
	"strings"
	"time"

	"github.com/gofrs/uuid"
	"google.golang.org/protobuf/proto"
	"gorm.io/gorm"

	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

// Transport - A C2 profile loaded onto an implant as an available transport.
type Transport struct {
	// Base
	ID             uuid.UUID `gorm:"primaryKey;->;<-:create;type:uuid;"`
	CreatedAt      time.Time `gorm:"->;<-:create;"`
	ImplantBuildID uuid.UUID // Compile-time transports
	SessionID      uuid.UUID // Runtime transports
	Priority       int32
	ProfileID      uuid.UUID
	Profile        *Malleable

	// Live
	Running       bool
	Attempts      int32
	Failures      int32
	RemoteAddress string // Set at registration time from the Connection
}

// ToProtobuf - The transport needs to be sent to a client console
func (t *Transport) ToProtobuf() *sliverpb.Transport {
	transport := &sliverpb.Transport{
		ID:      t.ID.String(),
		Order:   int32(t.Priority),
		Profile: t.Profile.ToProtobuf(),

		Running:       t.Running,
		Attempts:      t.Attempts,
		Failures:      t.Failures,
		RemoteAddress: t.RemoteAddress,
	}

	return transport
}

// TransportFromProtobuf - Given a transport passed by clients/implants, get a transport.
func TransportFromProtobuf(t *sliverpb.Transport) *Transport {

	transport := &Transport{
		ID:        uuid.FromStringOrNil(t.ID),
		ProfileID: uuid.FromStringOrNil(t.Profile.ID),
		Profile:   MalleableFromProtobuf(t.Profile),
		Priority:  t.Order,

		Running:       t.Running,
		Attempts:      t.Attempts,
		Failures:      t.Failures,
		RemoteAddress: t.RemoteAddress,
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

// Malleable - A complete C2 profile to be compiled into/ loaded by an implant.
type Malleable struct {
	// Identification
	ID               uuid.UUID `gorm:"primaryKey;->;<-:create;type:uuid;"`
	CreatedAt        time.Time `gorm:"->;<-:create;"`
	ImplantBuildID   uuid.UUID
	ContextSessionID uuid.UUID
	JobID            uuid.UUID
	// Transports       []*Transport `gorm:"many2many:profile_transports"` // Maybe not needed ?

	// Core
	Name            string
	Type            sliverpb.C2Type
	Channel         sliverpb.C2
	Direction       sliverpb.C2Direction
	Hostname        string
	Port            uint32
	Path            string
	ControlPort     uint32 // A generic ControlPort available to some C2 stacks (like Wireguard)
	KeyExchangePort uint32 // Generic key-exchange port for some protocols (like Wireguard)
	Domains         string // Comma separated string of domains (DNS & HTTP listeners)
	Canaries        bool

	// Technicals
	PollTimeout         int64
	MaxConnectionErrors int32
	ReconnectInterval   int64
	Interval            int64
	Jitter              int64
	Persistent          bool
	Active              bool
	CommDisabled        bool // Use the SSH-protocol based multiplexing on top of this C2 channel

	// HTTP related
	HTTP     *MalleableHTTP // Needs to be unmarshaled to a sliverpb.C2ProfileHTTP
	ProxyURL string
	Website  string

	// Identity & Security. TODO: Credential model integration
	// C2 Core
	CACertPEM         []byte
	CertPEM           []byte
	KeyPEM            []byte
	ServerFingerprint []byte
	// Advanced
	ControlServerCert []byte
	ControlClientKey  []byte
	LetsEncrypt       bool

	// If compiled with legacy generate, this is just a profile for compilation
	// We will not include those in most completions/commands that manipulate profiles.
	// Exception made of transports commands, which need to have access to those.
	Anonymous bool
}

// BeforeCreate - GORM hook
func (p *Malleable) BeforeCreate(tx *gorm.DB) (err error) {
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
func (p *Malleable) ToProtobuf() *sliverpb.Malleable {
	profile := &sliverpb.Malleable{
		// Core
		ID:               p.ID.String(),
		ContextSessionID: p.ContextSessionID.String(),
		Name:             p.Name,
		Type:             p.Type,
		C2:               p.Channel,
		Direction:        p.Direction,
		Hostname:         p.Hostname,
		Port:             p.Port,
		ControlPort:      p.ControlPort,
		KeyExchangePort:  p.KeyExchangePort,
		Path:             p.Path,
		Domains:          strings.Split(p.Domains, ","),
		Canaries:         p.Canaries,
		// Technicals
		PollTimeout:         p.PollTimeout,
		MaxConnectionErrors: p.MaxConnectionErrors,
		Persistent:          p.Persistent,
		Active:              p.Active,
		CommDisabled:        p.CommDisabled,
		Interval:            p.Interval,
		Jitter:              p.Jitter,
		// HTTP:
		ProxyURL: p.ProxyURL,
		Website:  p.Website,
		// Security & Identity
		Credentials: &sliverpb.Credentials{
			CACertPEM:         []byte(p.CACertPEM),
			CertPEM:           []byte(p.CertPEM),
			KeyPEM:            []byte(p.KeyPEM),
			ServerFingerprint: []byte(p.ServerFingerprint),
			ControlServerCert: []byte(p.ControlServerCert),
			ControlClientKey:  []byte(p.ControlClientKey),
		},
		LetsEncrypt: p.LetsEncrypt,
	}

	if p.HTTP != nil {
		profile.HTTP = p.HTTP.ToProtobuf()
	}

	return profile

}

// MalleableFromProtobuf - Convert C2 profile into Protobuf
func MalleableFromProtobuf(p *sliverpb.Malleable) (profile *Malleable) {
	profile = &Malleable{
		// Core
		ID:               uuid.FromStringOrNil(p.ID),
		ContextSessionID: uuid.FromStringOrNil(p.ContextSessionID),
		Type:             p.Type,
		Channel:          p.C2,
		Direction:        p.Direction,
		Name:             p.Name,
		// Target
		Hostname:        p.Hostname,
		Port:            p.Port,
		ControlPort:     p.ControlPort,
		KeyExchangePort: p.KeyExchangePort,
		Path:            p.Path,
		Domains:         strings.Join(p.Domains, ","),
		Canaries:        p.Canaries,
		Persistent:      p.Persistent,
		// Technicals
		PollTimeout:         p.PollTimeout,
		MaxConnectionErrors: p.MaxConnectionErrors,
		Active:              p.Active,
		Interval:            p.Interval,
		Jitter:              p.Jitter,
		CommDisabled:        p.CommDisabled,
		// HTTP:
		ProxyURL: p.ProxyURL,
		Website:  p.Website,
	}

	// Security & Identity
	if p.Credentials != nil {
		profile.CACertPEM = []byte(p.Credentials.CACertPEM)
		profile.CertPEM = []byte(p.Credentials.CertPEM)
		profile.KeyPEM = []byte(p.Credentials.KeyPEM)
		profile.ServerFingerprint = []byte(p.Credentials.ServerFingerprint)
		profile.ControlServerCert = []byte(p.Credentials.ControlServerCert)
		profile.ControlClientKey = []byte(p.Credentials.ControlClientKey)
		profile.LetsEncrypt = p.LetsEncrypt
	}

	if p.HTTP != nil {
		httpProfileData, _ := proto.Marshal(p.HTTP)
		profile.HTTP = &MalleableHTTP{
			ID:   uuid.FromStringOrNil(p.HTTP.ID),
			Data: httpProfileData,
		}
	} else {
		p.HTTP = &sliverpb.MalleableHTTP{}
	}

	return profile
}

// MalleableHTTP - Contains a protobuf specification of an HTTP C2 communication
// behaviour profile. This is used for storage and implant compilation purposes.
type MalleableHTTP struct {
	ID          uuid.UUID `gorm:"primaryKey;->;<-:create;type:uuid;"`
	MalleableID uuid.UUID

	UserAgent string // For search purposes and quick access
	Data      []byte // Needs to be unmarshaled to a sliverpb.C2ProfileHTTP
}

// ToProtobuf - Get a protobuf version  of this HTTP profile,
// so that we can compile it more easily, or send it on the wire
func (h *MalleableHTTP) ToProtobuf() *sliverpb.MalleableHTTP {
	p := &sliverpb.MalleableHTTP{
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
func (h *MalleableHTTP) BeforeCreate(tx *gorm.DB) (err error) {
	h.ID, err = uuid.NewV4()
	if err != nil {
		return err
	}
	return nil
}
